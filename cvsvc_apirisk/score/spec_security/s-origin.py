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
        self.pathstr    = pstr
        self.rulestr    = rstr
        self.children = {}
        self.childrenlist = []  # this is only used to store place-holder SpecNode list for []
        self.isAnAPI   = inapipath
        self.apiDef    = apidef
        if apidef and not apinode: # this happens when parent node creates a key which is apidef, but not yet the "node" which is self
            self.apiNode = self
        else:
            self.apiNode  = apinode
        self.refNode = None     # this refNode will be assigned a value if spec node dict is pointing to a $ref
        self.lineNums = ()
        if not myname == '*':   # the list element SpecNode is created only for the purpose of resolving references
            self.tree.addNewNodeForRef(self.pathstr, self)
        

    #
    # 1st pass of parsing, register reference to point to node if node has reference
    #
    def parseChildrenNodes(self):
        if type(self.specele) == dict : # only process dictionary and list, primative elements do not map to a SpecNode
            for k, v in self.specele.items():
                if k == '$ref' :       # first pass, just add a reference
                    if type(v) == tuple :
                        (refobj, lines) = v
                        self.tree.addReference(refobj, self)   # need to use v[0] as linemap has turned str into tuple
                        if not self.lineNums:
                            self.lineNums = lines['cvlrange26uel7Ao']
                    elif type(v) == str :
                        self.tree.addReference(v, self)   # need to use v[0] as linemap has turned str into tuple
                    self.children = {}   # reset children in case other dicts are added, will be replaced by $ref
                    break
                elif k == 'cvlrange26uel7Ao':  # lineNum mapping added to a dict obj
                    self.lineNums = v
                else:
                    if type(v) == dict or type(v) == list:  # dict or list (parameters: [<a list>]
                        api     = self.apiDef
                        apinode = self.apiNode
                        inpath  = self.isAnAPI
                        if k == "paths" and not api : # recorded the fact that the child nodes are part of an API paths definition, avoid corner case where an api is named "paths"
                            inpath = True
                            api    = ""
                            apinode= None
                        elif inpath and not api:  # this condition is true if we are just entering an api element in the paths dict
                            api=k
                            
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
                
            for listele in self.specele:
                if type(listele) == dict : 
                    self.childrenlist.append(SpecNode(rawspecele=listele,
                                                      tree=self.tree,
                                                      myname="*", pstr=self.pathstr + "/*",
                                                      rstr=self.rulestr + "->*",
                                                      apidef=self.apiDef, apinode=self.apiNode, inapipath=self.isAnAPI))
            for c in self.childrenlist:
                c.parseChildrenNodes()                        
        else: # TODO: raise exception, should not got here, child node should be a dict or a list before it is even created
            print("\n path \'%s\' ele is not a dictionary obj, it has type==%s element. Raise exception... \n" % (self.pathstr, type(self.specele)))
            return


                
    #
    # Add ref to refNode
    #
    def resolveMyRef(self, targetref):
        self.refNode = targetref
            
        
    
class SpecTree():
    
    def __init__(self, rawspecdata):
        self.spec = rawspecdata
        self.refs = {}
        self.globalreg = {}
        self.root = SpecNode(rawspecele=rawspecdata, tree=self, myname="#", pstr="#", rstr="#")
        self.root.parseChildrenNodes()

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
    # add to a global registry mapping path -> SpecNode
    #  used by ref resolution
    #
    def addNewNodeForRef(self, nodepath, ele):
        self.globalreg[nodepath] = ele
        
    #
    # called to resolve ref
    #
    def resolveRefs(self):
        if not self.refs:
            return
        for ref, nodes in self.refs.items():
            if not ref in self.globalreg : # TODO raise an exception
                print("\n invalid reference encountered ref=\'%s\' not found \n")
                continue
            for r in nodes :
                r.resolveMyRef(self.globalreg[ref])

    #
    # post ref resolve 
    #
    def cleanupAfterRefResolve(self):
        print ("\n---------- Global Keys (Cleaning up) %i global elements---------------------\n" % (len(self.globalreg)))
#        for p in self.globalreg.keys():
#           print ("%s" % (p))

        print ("\n-----------References (Cleaning up) %i references---------------------\n" % (len(self.refs)))
#        for r in self.refs.keys() :
#            print ("%s" % (r))
        self.globalreg = None # remove references to global objects no longer needed
        self.refs = None      # remove ref after


if __name__ == '__main__':

    usagestr  = "\n Usage: python3 spec_parse.py input_original_json_file_name \n"
    
    if (len(sys.argv) == 2):
        inputfname = sys.argv[1]
    else:
        print(usagestr)
        exit()

    if not os.path.exists(inputfname):
        print (" Original IMPSpARC JSON report file \"%s\" not found " % (inputfname))
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
        spectree.cleanupAfterRefResolve()
        f.close()

    endtime = datetime.datetime.now()
    dtime   = endtime - starttime
    print("\n\n ---------- run time measure: %s \n" % (dtime))

