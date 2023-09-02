#-------------------------------------------
#
# spec_parse
#  A utility for sparc2 to perform walks through
#   spec and construct identity "trees" that would
#   allow rule matching. Resolve $ref as well.
#
#------------------------------------------

import os
import json
import yaml
import sys
import datetime

from json_line import SaveLineRangeDecoder
from yaml_line import LineLoader as YamlLineLoader

#
# SpecNode holds information about a node and the path that leads to it
# A SpecNode rawspecele must be a 
#
class SpecNode():
    def __init__(self, rawspecele, tree, myname, pstr, rstr, apidef="", apinode=None, inapipath=False):
        self.specele    = rawspecele
        self.myname     = myname
        self.tree       = tree
        self.pathstr    = pstr  # string separated by '/'
        self.rulestr    = rstr  # string separated by '->'
        self.children = {}
        self.childrenlist = []  # this is only used to store place-holder SpecNode list for []

        self.isAnAPI   = inapipath # this boolean flag is set to any node that is api path, including the "paths" node itself
        self.apiDef    = apidef    # this is only set to the api path string, to be used when a violation is raised
        if apidef and not apinode: # this happens when parent node creates a key which is apidef, but the "node" which is self
            self.apiNode = self
        else:
            self.apiNode  = apinode # inheriting the apiNode pointing to the api path root node
        if apidef and apinode : # this must be a sub api path node, add to api match list for relative match
            self.tree.addAPINode(apidef, self.rulestr, self, self.apiNode)   
        self.refNode = None     # this refNode will be assigned a value if spec node dict is pointing to a $ref
        self.isCircularRef = False
        self.lineNums = ()

        if not self.isAnAPI :  # if not an API node, add it to the global list
            self.tree.addGlobalNode(self.rulestr, self)
            
        if not myname == '*':   # the list element SpecNode is created only for the purpose of resolving references
            self.tree.addNewNodeForRef(self.pathstr, self)
        

    #
    # 1st pass of parsing, register reference to point to node if node has reference
    #
    def parseChildrenNodes(self):
        if type(self.specele) == dict : # only process dictionary and list, primative elements do not map to a SpecNode
            for k, v in self.specele.items():
                if k == '$ref' :       # first pass, just add a reference
                    #import pdb;pdb.set_trace()
                    if type(v) == tuple :
                        (refobj, lines) = v
                        self.tree.addReference(refobj, self)   # need to use v[0] as linemap has turned str into tuple
                        if not self.lineNums:
                            self.lineNums = lines['cvlrange26uel7Ao']
                    elif type(v) == str :
                        self.tree.addReference(v, self)   # v is a string, no linenum
                    self.children = {}   # reset children in case other dicts are added, will be replaced by $ref
                    break
                elif k == 'cvlrange26uel7Ao':  # lineNum mapping added to a dict obj
                    self.lineNums = v
                else:   # only create child node if the value itself is dict or a list, otherwise, current specele is good for final element matching
                    if type(v) == dict or type(v) == list:  # dict or list (parameters: [<a list>]
                        api     = self.apiDef
                        apinode = self.apiNode
                        inpath  = self.isAnAPI
                        if k == "paths" and not api : # recorded the fact that the child nodes are part of an API paths definition, avoid corner case where an api is named "paths" by checking to make sure api definition is NOT set, if it is set, it is already part of an api
                            inpath = True   # inpath means it is creating a path element 
                            api    = ""
                            apinode= None
                        elif inpath and not api:  # this condition is true if we are just entering an api element in the paths dict
                            api=k   # the child note matching the api is about to be created, therefore api definition is set but not node
                            
                        if not self.children :
                            self.children = {}
                        self.children[k] = SpecNode(rawspecele=v,
                                                    tree=self.tree,
                                                    myname=k, pstr=self.pathstr + "/" + k,
                                                    rstr=self.rulestr + "->" + k, 
                                                    apidef=api, apinode=apinode, inapipath=inpath)
            #
            # after processing all dict elements, recursively parse children
            #
            for c in self.children.values():
                c.parseChildrenNodes()
        elif type(self.specele) == list: # in the rules, we use <name> -> * -> to refer to the list, a special case to add current node to the rule list
            #
            # first extract line range tuple from end of the list if any (json linenum)
            #
            if self.specele and type(self.specele[len(self.specele)-1]) == dict and 'cvlrange26uel7Ao' in self.specele[len(self.specele)-1] :
                line = self.specele.pop()
                self.lineNums = line['cvlrange26uel7Ao']

            #
            # as it is a list, use a childrenlist instead of children (dict) to store it as child ele has no name
            #
            for listele in self.specele:
                if type(listele) == dict : 
                    self.childrenlist.append(SpecNode(rawspecele=listele,
                                                      tree=self.tree,
                                                      myname="*", pstr=self.pathstr + "/*",
                                                      rstr=self.rulestr + "->*",
                                                      apidef=self.apiDef, apinode=self.apiNode, inapipath=self.isAnAPI))
            #
            # recursively process children nodes
            # 
            for c in self.childrenlist:
                c.parseChildrenNodes()                        
        else: # TODO, raise exception, this should not happen as root of a spec is dict
            print("\n path \'%s\' ele is not a dictionary obj, it has type==%s element. Raise exception... \n" % (self.pathstr, type(self.specele)))
            return


    #
    # check for circular ref, return a trace of circular ref
    #  return [] if no circular ref is found
    #
    def checkCircularRef(self, parentlist=[]):
        if self in parentlist:
            parentlist.append(self)
            return parentlist

        myplist = parentlist.copy()
        myplist.append(self)

        if self.refNode:
            result = self.refNode.checkCircularRef(myplist)
            if result :
                return result

        if self.children:
            for k, v in self.children.items():
                plist = myplist.copy()
                result = v.checkCircularRef(plist)
                if result:
                    return result
        if self.childrenlist:
            for v in self.childrenlist: 
                plist = myplist.copy()
                result = v.checkCircularRef(plist)
                if result:
                    return result
        return []  # no circular ref found in child
        
    #
    # Add ref to refNode
    #
    def resolveMyRef(self, targetref):
        self.refNode = targetref
        circularlist = self.checkCircularRef()
        if circularlist:
            self.tree.addCircularReference(self, circularlist)
        
    #
    # Deprecated, need more efficient way of handling references
    #
    #
    # 
    # addRefChildNodes: being called from the original $ref to
    #  targetRef Node, add the target Ref Node to the api path
    #  with a different rulestr coming from the origin
    #
    # Even notes with circular dependencies will be called to add
    #  childNodes' to its path.
    #
    def addRefChildNodes(self, newrefrulestr, apidef='', apinode=None, callers=[]):
        if self in callers:
            return

        mycallers = callers.copy()
        mycallers.append(self)
            
        if self.refNode:
            self.refNode.addRefChildNodes(newrefrulestr, apidef, apinode, mycallers)

        if self.children:
            for k, v in self.children.items():
                if not apidef or not apinode:
                    self.tree.addGlobalNode(newrefrulestr+"->"+k, v)
                else:
                    self.tree.addAPINode(apidef, newrefrulestr+"->"+k, v, apinode)
                mycallers = callers.copy()
                mycallers.append(self)                    
                v.addRefChildNodes(newrefrulestr+"->"+k, apidef, apinode, callers=mycallers)
        if self.childrenlist:
            for v in self.childrenlist:
                if not apidef or not apinode:
                    self.tree.addGlobalNode(newrefrulestr+"->*", v)
                else:
                    self.tree.addAPINode(apidef, newrefrulestr+"->*", v, apinode)
                mycallers = callers.copy()
                mycallers.append(self)                                        
                v.addRefChildNodes(newrefrulestr+"->*", apidef, apinode, callers=mycallers)
            

    #
    # updateRefNodePaths: add ref 
    #
    def updateRefNodePaths(self):
        if not self.refNode: # this shound't happen, report an error
            return 

        self.refNode.addRefChildNodes(self.rulestr, apidef=self.apiDef, apinode=self)
    #
    # end deprecated Ref node path expansions
    #
                                      
class SpecTree():
    
    def __init__(self, rawspecdata):
        self.spec = rawspecdata
        # refs and globalreg are meant to store references global "paths" to resolve $refs in specs
        self.refs = {}
        self.globalreg = {}
        self.perapinodes = {}   # perapinodes is a dict mapping api name to a list of nodes defined below that api, used for relative path matches of rules
        self.targetrefnodes = {} # it is a hash key=ref, val={<actual global path>: targetrefnode}
        self.circularrefs = {}   # list of circular references detected along the way
        self.nonapinodes = {}   # all the other global apinodes
        self.root = SpecNode(rawspecele=rawspecdata, tree=self, myname="#", pstr="#", rstr="#")
        self.root.parseChildrenNodes()

    #
    # adding a node to apidef, new rulestr is added to help with $ref
    #   subnode is the actual "leaf" node
    #   apinode is the node holding the API definition
    #
    def addAPINode(self, apidef, rulepath, subnode, apinode):
        if apidef in self.perapinodes:
            self.perapinodes[apidef].append((rulepath, subnode, apinode))
        else:
            self.perapinodes[apidef]=[(rulepath, subnode, apinode)]

    #
    # adding a node to nonapi globalnode
    #
    def addGlobalNode(self, rulepath, subnode):
        if rulepath in self.nonapinodes: 
            self.nonapinodes[rulepath].append(subnode)
        else:
            self.nonapinodes[rulepath]=[subnode]
            
    #
    # adding a reference that needs to be resolved
    #
    def addReference(self, refstr, callerele):
        if not refstr.startswith("#") :   # not a supported local reference, URL/file reference not supported, skip, TODO: raise low violation
            print("\n\n Reference not supported \'%s\', skipping \n\n" % (refstr))
            return 
        if refstr in self.refs :
            self.refs[refstr].append(callerele)
        else:
            self.refs[refstr]=[callerele]

    #
    # for debugging purpose and in future, report error
    #
    def addCircularReference(self, refstartnode, reflist):
        self.circularrefs[refstartnode.pathstr] = reflist
        
    #
    # add to a global registry mapping path -> SpecNode
    #  used by ref resolution
    #
    def addNewNodeForRef(self, nodepath, ele):
        self.globalreg[nodepath] = ele

    #
    # update TargetRefNodes for later rule checks
    #  target ref nodes should be checked against API
    #  related violations
    #
    def updateTargetRefNodes(self, ref):
        if ref in self.targetrefnodes : # possible that a target ref node has been added
            return

        allnodes = []
        for k, node in self.globalreg.items() :
            if k.startswith(ref) :  # add all children nodes, not just the $ref node
                allnodes.append(node)
        self.targetrefnodes[ref] = allnodes



    # def get_parameter_count(self, specele):
    #     fo
    #
    # called to resolve ref
    #
    def resolveRefs(self):
        #import pdb;pdb.set_trace()
        if not self.refs:
            return
        import pdb;pdb.set_trace()
        for ref, nodes in self.refs.items():
            if not (ref in self.globalreg) : # TODO raise an exception
                print("\n Error in spec, invalid reference encountered ref=\'%s\' not found \n")
                continue
            for r in nodes : # all the parent nodes that references the same ref
                r.resolveMyRef(self.globalreg[ref])
                #parameter_count = self.get_parameter_count(self.globalreg[ref].specele)

        #
        # another loop, after all references are resolved, to
        #  add global nodes that are being referenced into a
        #  list of nodes that will be evaluated 
        #
        for ref, nodes in self.refs.items():
            if not (ref in self.globalreg) : # exception should have been raised previously
                continue
            #
            # add all nodes that starts with "ref" to the targetrefnodes list
            #
            self.updateTargetRefNodes(ref)
        #
        #  Need more efficient ways instead of expanding all the
        #   node paths
        #
#        for ref, nodes in self.refs.items():
#            for r in nodes :
#                r.updateRefNodePaths()

    #
    # post ref resolve 
    #
    def cleanupAfterRefResolve(self, debug=False, debugRef=False):
        print ("\n---------- Global Keys (Cleaning up) %i global elements---------------------\n" % (len(self.globalreg)))
#        for p in self.globalreg.keys():
#           print ("%s" % (p))

        print ("\n-----------References (Cleaning up) %i references---------------------\n" % (len(self.refs)))
        self.globalreg = None 
        #self.refs = None      # Changed due to $ref handling, preserve globalreg in case in future we want to report how many "callers"/"parents" API nodes are affected by a certain violation

        nrules = 0
        if debug: 
            print ("\n----------- Per APIs for matching %i apis ---------------------\n" % len(self.perapinodes))
        for api, rlist in self.perapinodes.items():
            if debug: 
                print("api=\'%s\' %i rules--> " % (api, len(rlist)))
            for rn in rlist: 
                (rulestr, vnode, apinode) = rn
                if debug: 
                    print ("     r=\'%s\'" % (rulestr))
                nrules += 1
                
        if debug:
            print ("\n----------- Global Names %i nodes ---------------------\n" % len(self.nonapinodes))
            for p in self.nonapinodes.keys():
                print("   \'%s\' " % (p))
            
        nrefnodes = 0
        if debug: 
            print ("\n----------- Nodes referenced by APIs that need checking, number of $ref: %i ---------------------\n" % len(self.targetrefnodes))
        for ref, rlist in self.targetrefnodes.items():
            if debug: 
                print("$ref=\'%s\' %i rules--> " % (ref, len(rlist)))
            for rn in rlist: 
                if debug: 
                    print ("     r=\'%s\'" % (rn.rulestr))
                nrefnodes += 1
                
        print ("\n----------- Global Names %i nodes ---------------------\n" % len(self.nonapinodes))
        print ("\n----------- Per APIs for matching %i apis %i nodes total ---------------------\n" % (len(self.perapinodes), nrules))
        print ("\n----------- Nodes referenced by API: %i $ref and %i nodes total ---------------------\n" % (len(self.targetrefnodes), nrefnodes))
        print ("\n----------- Circular Reference detected: %i  ---------------------\n" % (len(self.circularrefs)))
        if debugRef:
            for p, circularlist in self.circularrefs.items(): 
                print("\n Circular reference found in node '%s' ref trace ---> " % (p))
                for v in circularlist:
                    print ("   %s " % v.pathstr)
        self.circularrefs = {}

                
        
if __name__ == '__main__':

    usagestr  = "\n Usage: python3 spec_parse.py spec_file_name \n"
    
    if (len(sys.argv) == 2):
        inputfname = sys.argv[1]
    else:
        print(usagestr)
        exit()

    if not os.path.exists(inputfname):
        print (" Specificaiton file \"%s\" not found " % (inputfname))
        exit()

    starttime = datetime.datetime.now()
    with open(inputfname, encoding='utf8') as f:
        if inputfname.endswith(".json"): 
            indata = json.load(f, cls=SaveLineRangeDecoder)
        elif inputfname.endswith(".yaml"):
            raw_spec = yaml.safe_load(f)
            f.seek(0)
            loader = YamlLineLoader(f)
            indata = loader.get_single_data()
        else:
            print (" file must be json or yaml... to raise exception.")

        spectree = SpecTree(indata)
        spectree.resolveRefs()
        spectree.cleanupAfterRefResolve(debug=True, debugRef=False)  # if running spec_parse itself, print the spec tree nodes
        f.close()

    endtime = datetime.datetime.now()
    dtime   = endtime - starttime
    print("\n\n ---------- run time measure: %s \n" % (dtime))

