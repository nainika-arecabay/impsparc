#-------------------------------------------
#
# Rules_util
#
# Parse the rule.json file
#  A set of rules that will be separated into
#   - absolute path match rules and then
#   - relative path match rules
#
# Evaluate rules and collect all violations
#
#  Result is a RuleSet Object that will be used
#   to evaluate all rules and raise violations
#   to be collected.
#
#------------------------------------------

import os
import json
import yaml
import sys
import datetime
import re

from json_line import SaveLineRangeDecoder
from yaml_line import LineLoader as YamlLineLoader


golbal_ref = []
from sp2_reporting import Violation

from enum import Enum

class IdMatchType(Enum):
    GLOBAL  =1
    APILOCAL=2

class ExtractValueFrom(Enum):
    KEY  =1
    VALUE=2
    
class ExpectValueType(Enum):
    INT      = 1
    STR      = 2

class ConditionType(Enum):
    VALCOMPARE   = 1
    VALISEMPTY   = 2
    KEYISMISSING = 3

#
# Rule holds a single rule
#
class Rule():
    def __init__(self, onerule):
        self.idenStr  = onerule["identifier"]
        self.op       = onerule["condition"]
        self.val      = onerule["value"]
        self.toIgnore = False

        self.matchKey    = ""
        self.idregEx     = None
        self.idMatchType = None
        self.valFrom     = None
        self.valType     = None
        self.opregEx     = None
        self.condType    = None
        
        self.createIdentRe()
        self.decideValType()

    def checkSelf(self, debug=False):
        if debug: 
            print("    Iden search regEx=\'%s\', matching key=\'%s\', extract from %s, looking for ValType %s, CondType %s <--- original rule info: [\'%s\' (iden) \'%s\'(condition) \'%s\'(val)]\n" % (self.idregEx, self.matchKey, self.valFrom, self.valType, self.condType, self.idenStr, self.op, self.val))

        if self.condType == ConditionType.KEYISMISSING and not self.matchKey:
            print("    --- Error: rule is to decide if key is missing but no matchKey is found")
            return
        
        if self.condType == ConditionType.VALISEMPTY and (not self.matchKey):
            print("    --- Error: rule is to decide if an element is empty but matchKey is not defined.")
            return        
        
        if (not (self.valFrom == ExtractValueFrom.KEY) or not self.valFrom) and self.condType == ConditionType.KEYISMISSING : #error, ignore this rule, future, report it.
            print("    --- Error (rule will be ignored): match condition is checking if a key is missing, but the value specified is to extract from a value \n")
            self.toIgnore = True
            return

        if self.valFrom == ExtractValueFrom.VALUE and not self.matchKey :
            print("    --- Error (rule will be ignored): matching a value of a given key, but no identity path is specified to find the dictinary in which the key:value pair can be extracted. Consider adding at least ->* to the identity string \'%s\' to match any keys within the dictionary or a specific key name.\n" % self.idenStr)
            self.toIgnore = True
            return
        
        
    def decideValType(self):
        self.condType = ConditionType.VALCOMPARE
        if not self.valFrom :
            self.valFrom = ExtractValueFrom.VALUE
        if self.op == "<" or self.op == "<=" or self.op == ">" or self.op == ">=" or self.op == "==" or self.op == "/=":
            if not (type(self.val) == int) and not self.val.isnumeric():
                print("-- Error, todo, raise exception: value \'%s\' is not numeric while condition \'%s\' expects numeric value.\n" % (self.val, self.op))
                exit()
                return
            if not (type(self.val) == int):
                self.val = int(self.val)  # convert from str to int
            self.valType = ExpectValueType.INT
        elif self.op == "eq" or self.op == "ne":
            self.valType = ExpectValueType.STR
        elif self.op == "pattern-match":
            self.valType = ExpectValueType.STR
            self.opregEx = re.compile(self.val)  # pre-compile regex match
        elif self.op == "is-missing":
            self.valFrom = ExtractValueFrom.KEY
            self.condType = ConditionType.KEYISMISSING
            if self.val == "True":
                self.val = True
            elif self.val == "False":
                self.val = False
            else:
                print("-- Error, todo, raise exception: value \'%s\' is not True/False while condition \'%s\' expects a boolean value True/False.\n" % (self.val, self.op))
                exit()
        elif self.op == "is-empty":
            self.condType = ConditionType.VALISEMPTY
            if self.val == "True":
                self.val = True
            elif self.val == "False":
                self.val = False
            else:
                print("-- Error, todo, raise exception: value \'%s\' is not True/False while condition \'%s\' expects a boolean value True/False.\n" % (self.val, self.op))
                exit()
        else:
            print("-- Error (rule will be ignored) todo, raise exception: op \'%s\' not recognized" % self.op)
            self.toIgnore = True
            
        return

    def createIdentRe(self):
        # if self.idenStr == '#->security->*':
        #     import pdb;pdb.set_trace()
        if self.idenStr.startswith("#"): 
            self.idMatchType = IdMatchType.GLOBAL
            self.globalResult = False  # a rule should record a global result once a single global match is evaluated to true
        else:
            self.idMatchType = IdMatchType.APILOCAL

        idmstr = self.idenStr # make a copy so original match str is kept for reporting purposes
        if idmstr.endswith("__key__"):
            self.valFrom = ExtractValueFrom.KEY
            idmstr = idmstr.rstrip("__key__")  # recorded the fact that it is keys, 


        if "->" in idmstr : # it is rare that id matching just a single key, but if it is, leave it alone, can be the case 
            ids = idmstr.split("->")
            self.matchKey = ids[-1]   # save last key to match, can be a *
            matchstr = "->".join(ids[0:-1])
        else:  # just a single match key, a simple example is operation__key__ , matchKey == ""
            matchstr = idmstr

        #
        # expand the "operation" keyword
        #            
        if matchstr.startswith("operation"):  # a special case, operation as first token matches #->paths-><apipath>-><methods such as put/get/post/delete
            matchstr = matchstr.replace("operation", "^#->paths->[a-zA-Z/]+->[a-zA-Z]+")

        if not matchstr.endswith('*'):
            matchstr = matchstr + "$" # we will look for substring anchored towards the end
        if matchstr.startswith("#") : # global search, make sure it search from beginning
            matchstr = "^"+matchstr
    
        self.idregEx = re.compile(matchstr)   # store the regEx match
        return

    #
    # due to the linenumrange hack into JSON, values will be
    #  turned into a tuple of (<originalval>, (line, line))
    #
    # if for any reason the line number isn't there, just extract the
    #  originalv and (0,0) as a place for linenum
    #
    def getValFromTuple(self, t):
        if type(t) == str :   # this is the normal case if we are parsing yaml, obtain line num elsewhere
            return (t, (0,0))

        if type(t) == tuple: 
            (originalv, linedict) = t
            if type(linedict) == dict and 'cvlrange26uel7Ao' in linedict:
                return (originalv, linedict['cvlrange26uel7Ao'])
            else:
                return (originalv, (0,0))
        else:
            return (t, (0,0))   # return t if it is any other types

    def doValsMatch(self, leftval):
        #
        # a hack, TODO: to properly handle with linenum extraction
        #
        if type(leftval) == str and leftval.startswith("__line__") :
            leftval = leftval.lstrip("__line__")
        #
        
        lval = ""
        if self.valType == ExpectValueType.INT:
            if type(leftval) == int :
                lval = leftval
            elif leftval.isnumeric():
                lval = int(leftval)
            else:
                print(" -- Match error: left val \'%s\' is not numeric but int is expected for comparison id=\'%s\' op=\'%s\' val=\'%s\'.\n" % (leftval,self.idenStr, self.op, self.val))
                return False  # no match, the left value is not numeric
            
            if self.op == ">":
                return lval > self.val
            elif self.op == ">=":
                return lval >= self.val
            elif self.op == "==":
                return lval == self.val
            elif self.op == "/=":
                return not (lval == self.val)
            elif self.op == "<":
                return lval < self.val
            elif self.op == "<=":
                return lval <= self.val
            else:
                return False
        else:
            lval = leftval
            if self.op == "eq" :
                return lval == self.val
            elif self.op == "ne" :
                return not (lval == self.val)
            elif self.op == "pattern-match":
                return not (self.opregEx.search(self.val) == None )


    #
    # Perform match given a SpecNode
    #  SpecNode points to either a dict (normal case) or a list (matching require a *)
    #  In all other cases, 
    #
    def matchANode(self, node):
        #
        # add handling of $ref
        #
        # if node.myname == 'required':
        #     import pdb;pdb.set_trace()
        # print(node.myname)
        if not node.refNode: 
            target = node.specele
        else:
            target = node.refNode.specele  # if refNode exists, meaning <node> itself is $ref, try to find a match in refNode
        #print(self.matchKey, target)
        # if self.matchKey == '&':
        #     import pdb;pdb.set_trace()
        if not (type(target) == dict): # not a dictionary, that can only occur if it is pointing to a list
            if (self.matchKey == "*"): # a list must match against "*" matchKey
                #m = "nn"
                print(" Internal Error, to raise exception, matching a node not a dict but matchKey \'%s\' is not \'*\' (iden=\'%s\', op=\'%s\', val=\'%s\')" % (self.matchKey, self.idenStr, self.op, self.val))
                exit()
            else: # match key == * into a list
                if type(target) == list:
                    for v in target:
                        if self.condType == ConditionType.VALISEMPTY :  # checking if val is empty, this is checking if an element of a list is empty
                            r = (not v)
                            return (v == self.val, target)     # self.val is a boolean itself

                        (leftval, __) = self.getValFromTuple(v)
                        if self.doValsMatch(leftval): # match one of the value in the list
                            return (True, v)
                    return (False, None)   # no match
                else: # we should not get here actually
                    (leftval, __) = self.getValFromTuple(target)
                    if self.doValsMatch(leftval): # match one of the value in the list
                        return (True, target)
                    return (False, None)
        else: # match against a dictionary
            return self.matchDictNode(target, node)
            
    def matchDictNode(self, target, node):
        if self.condType == ConditionType.KEYISMISSING : 
            if self.matchKey:  # simply check if marchKey is in the dict
                r = not (self.matchKey in target)                           # key is missing means not in target
                return (r == self.val, target)
            else: # an error condition, self.matchKey is not there
                print(" Internal Error, to raise exception, rule does not contain a match key while it is determining if a key is missing (iden=\'%s\', op=\'%s\', val=\'%s\')" % (self.idenStr, self.op, self.val))
                exit()
                return (False, None)

        #
        # It is either VALCOMPARE or VALISEMPTY
        #
        leftval = ""
        if self.valFrom == ExtractValueFrom.KEY and not self.matchKey: # value is from the current key itself
            leftval = node.myname   # this is the case where operation->__key__, matchKey is "", now take the node's name
            r = self.doValsMatch(leftval)  # perform the match and done
            if r:
                return (True, target)
            else:
                return (False, None)
        elif not self.matchKey:     # no other cases where self.matchKey should be 0
            print(" Internal Error, to raise exception, rule does not contain a match key while it is not extracting value from a key (iden=\'%s\', op=\'%s\', val=\'%s\')" % (self.idenStr, self.op, self.val))
            exit() # quickly exit to flag internal error
            return (False, None)            # this is an error condition, matchKey must be defined for value compare

        #
        # normal case of comparing target[self.matchKey] self.op self.val
        #
        if not (self.matchKey == "*") :  # not a match all
            if not (self.matchKey in target):   # no such key, no match
                return (False, None)                   # no match
            
            (leftval, __) = self.getValFromTuple(target[self.matchKey])  # look up matchKey
            if self.condType == ConditionType.VALISEMPTY :  # checking if val is empty
                r = not leftval
                return (r == self.val, target)     # self.val is a boolean itself
            r = self.doValsMatch(leftval)
            if r :
                return (True, target)
            else:
                return (False, None)
        else: # matchKey is *, loop through all k/v pair
            for k, v in target.items():
                leftval = ""
                if self.valFrom == ExtractValueFrom.KEY :
                    leftval = k
                else:
                    (leftval, __) = self.getValFromTuple(v)
                if leftval == 'cvlrange26uel7Ao':  # ToDo, better handle special linenum indicator
                    continue
                if self.doValsMatch(leftval): # match one of the value in the target dict
                    return (True, v)

        return (False, None) # default
        
#
# Match is paired with Rule to hold
#  a specific match against a specific node
#  For a global match, Match : Rule == 1 : 1
#  For an API match, there will be one Match per API Node Match : Rule = <n of API Nodes> : 1
#
#  A match also recorded the match result, per node. Multiple matches combined to triggered
#   a violation
#
class Match():
    def __init__(self, rule):
        self.rule=rule
        self.globalResult         = False # record the global result, local API results are not recorded
        self.globalMatchedSpecEle = None  # this is the actual spec element the match occurs


    #
    # match a rulepath against a rule's idregEx to see if the node itself is a match
    #
    def isNodeMatch(self, rulepath, idmtype):
        #if not (self.rule.idMatchType == idmtype):  # not the right type
        #    return False
        result =  self.rule.idregEx.search(rulepath) 
#        print("  Result: %s   ----> checking rule \'%s\', with regEx\'%s\', against path \'%s\'\n" % (result, self.rule.idenStr, self.rule.idregEx, rulepath))
        return not (result == None)

    #
    # match a targetnode's "left value" to the rule's "right value"
    #
    def evalMatch(self, targetnode):
        #import pdb;pdb.set_trace()
        if self.rule.idMatchType == IdMatchType.GLOBAL and self.globalResult :   # the match has been evaluated to true
            return (self.globalResult, '')

        #import pdb;pdb.set_trace()
        #try:
        (result, specele)= self.rule.matchANode(targetnode)

            #(result, specele) = self.rule.matchANode(targetnode)
        if result and self.rule.idMatchType == IdMatchType.GLOBAL :
            self.globalResult = result
            self.globalMatchedSpecEle = specele
        return (result, specele)

    def isMatchGlobal(self):
        return self.rule.idMatchType == IdMatchType.GLOBAL

#
# MatchSet sets up a new MatchSet for rules
#
class MatchSet():
    
    def __init__(self, rset=None):
        if not rset :
            return
        self.num_evaluations = 0
        self.ruleSet = rset
        self.globalResult  = False 

        self.matchSet = []
        for r in rset.ruleSet:
            if not r.toIgnore: 
                self.matchSet.append(Match(r))

        self.allMatchGlobal = True
        for m in self.matchSet:
            if not m.isMatchGlobal() :
                self.allMatchGlobal = False

    def performGlobalMatches(self, globalnodes, vios, linenum_mapping, debug=False):
        #import pdb;pdb.set_trace()
        num_evaluations = 0
        for r, nodes in globalnodes.items():
            #print("r", r)
            for nod in nodes:
                #print("n", nod)
                allmatch = True
                # raw_rule = '(%s %s %s)%s' % (
                #     r, self.ruleSet.op, self.ruleSet.val,
                #     n.lineNums[0])
                for i, m in enumerate(self.matchSet):
                    num_evaluations = num_evaluations + 1
                    raw_rule = '(%s->%s %s %s)[%s]' % (
                        r, m.rule.idenStr.rsplit('->', 1)[-1], m.rule.op, m.rule.val,
                        '0')
                    #import pdb;pdb.set_trace()
                    if i == 0:
                        v_entity = raw_rule
                    else:
                        v_entity = '%s and %s' % (v_entity,  raw_rule)
                    if m.isNodeMatch(r, IdMatchType.GLOBAL) :
                        # print(" -- Node found in global list, r\'%s\' matches path\'%s\'\n" % ( m.rule.idenStr, r))
                        #import pdb;pdb.set_trace()
                        #if nod
                        (result, rawnode) = m.evalMatch(nod)
                        if not result:
                            allmatch = False
                    else:
                        allmatch = False
                if allmatch:
                    self.globalResult = True  # A MatchSet is done after checking only global nodes
                    if debug:
                        print("  !!-- Rule match found in node r\'%s\', matches rule id=\'%s\'\n" % (r, self.ruleSet.id))
                    golbal_ref.append(v_entity)
                    vios.append(Violation(self.ruleSet, nod, v_entity))
        if self.allMatchGlobal and (not self.globalResult) :
            if debug: 
                print("  !!-- Debug: No match found for rule id=\'%s\ after global check'\n" % (self.ruleSet.id))

        return num_evaluations
            
    def copyMatch(self, originSet):
        self.ruleSet = originSet.ruleSet
        
        self.matchSet = []
        for m in originSet.matchSet :
            if m.isMatchGlobal() :
                self.matchSet.append(m)              # copy the original global match
            else:
                self.matchSet.append(Match(m.rule))  # create a new match for local api match


    def performPerAPIMatches(self, apidef, nodes, vios, linum_mapping, debug=False):
        num_evaluations = 0
        #import pdb;pdb.set_trace()
        for (r, n, apinode) in nodes:
            allmatch = True
            # raw_rule = '(%s %s %s)%s' % (
            #     r, m.rule.op, m.rule.val,
            #     n.lineNums[0])
            for i, m in enumerate(self.matchSet):
                num_evaluations = num_evaluations + 1
                #import pdb;pdb.set_trace()
                #print(m.rule.idenStr.rsplit('->', 1)[-1])
                #print(n.lineNums)
                raw_rule = '(%s->%s %s %s)[%s]' % (
                    r, m.rule.idenStr.rsplit('->', 1)[-1], m.rule.op, m.rule.val,
                    n.lineNums)
                if i == 0:
                    v_entity = raw_rule
                else:
                    v_entity = '%s and %s' % (v_entity, raw_rule)
                if m.isMatchGlobal() :
                    if m.globalResult : # a global match is fulfilled
                        continue
                    else:
                        allmatch = False
                        break
                if m.isNodeMatch(r, IdMatchType.APILOCAL) :
                    if debug: 
                        print(" -- Node found in api list, r\'%s\' matches path\'%s\'\n" % ( m.rule.idenStr, r))
                    (result, rawnode) = m.evalMatch(n)
                    if not result:
                        allmatch = False
                        break
                else:
                    allmatch = False
            if allmatch:
                if debug: 
                    print("       API rule check match found in node r\'%s\', matches rule id=\'%s\'\n" % (r, self.ruleSet.id))
                golbal_ref.append(v_entity)
                vios.append(Violation(self.ruleSet, n, v_entity, apiDef=n.apiDef, apiNode=apinode))
        return num_evaluations
                
    def performRefMatches(self, refdef, nodes, vios, linum_mapping, debug=False):
        num_evaluations = 0
        for refnode in nodes:
            allmatch = True
            for i, m in enumerate(self.matchSet):
                num_evaluations = num_evaluations + 1
                raw_rule = '(%s->%s %s %s)[%s]' % (
                    refnode.rulestr, m.rule.idenStr.rsplit('->', 1)[-1], m.rule.op, m.rule.val,
                    refnode.lineNums)
                if i == 0:
                    v_entity = raw_rule
                else:
                    v_entity = '%s and %s' % (v_entity, raw_rule)
                if m.isMatchGlobal() :
                    if m.globalResult : # a global match is fulfilled
                        continue
                    else:
                        allmatch = False
                        break
                if m.isNodeMatch(refnode.rulestr, IdMatchType.APILOCAL) :
                    if debug: 
                        print(" -- Node found in api list, r\'%s\' matches path\'%s\'\n" % ( m.rule.idenStr, refnode.rulestr))
                    (result, rawnode) = m.evalMatch(refnode)
                    if not result:
                        allmatch = False
                        break
                else:
                    allmatch = False
            if allmatch:
                if debug: 
                    print("       Referenced node rule check match found in node r\'%s\', matches rule id=\'%s\'\n" % (refnode.rulestr, self.ruleSet.id))
                golbal_ref.append(v_entity)
                vios.append(Violation(self.ruleSet, refnode, v_entity))

        file_out = open("new_voi.data", 'w')
        golbal_ref.sort()
        for data in golbal_ref:
            file_out.write("%s\n" % data)

        return num_evaluations

                
#
# A definition of a set of rules with a rule-id,
#  matching all in the ruleSet will trigger a violation
#
# toIgnore flag is used to skip rules that can not be supported.
#  for example, "embedded-run" is not supported
#
class RuleSet():
    def __init__(self, ruledata):
        self.id       = ruledata["ruleid"]
        self.info     = ruledata
        self.toIgnore = False
        self.ruleSet  = []
        for r in ruledata["rule"]:
            onerule = Rule(r)
            if not onerule.toIgnore :
                self.ruleSet.append(onerule)
            else:
                self.toIgnore = True  # one rule can't be supported, ignore the whole rule
                break                 # a single rule error is enough, abandon this RuleDef

    def printSelf(self):
        print(" Id=\'%s\', Ignore=%s" % (self.id, self.toIgnore))
        if not self.toIgnore :
            for r in self.ruleSet:
                r.checkSelf(debug=True)
                if r.toIgnore: # if rule is bad after check, mark the entire ruleSet bad and ignore
                    self.toIgnore = True

        
if __name__ == '__main__':

    usagestr  = "\n Usage: python3 rules_util.py rulefile \n"
    
    if (len(sys.argv) == 2):
        inputfname = sys.argv[1]
    else:
        print(usagestr)
        exit()

    if not os.path.exists(inputfname):
        print (" Rules file \"%s\" not found " % (inputfname))
        exit()

    starttime = datetime.datetime.now()
    with open(inputfname, encoding='utf8') as f:
        if inputfname.endswith(".json"): 
            indata = json.load(f)
        else:
            print (" rule file must be json to raise exception.")

        rules={}
        for r in indata["rules"] : 
            rdef = RuleSet(r)
            if not rdef.toIgnore: 
                rules[rdef.id] = rdef

        matchsets = []
        for k, r in rules.items():
            matchsets.append(MatchSet(r))
            r.printSelf()
            
        f.close()

    endtime = datetime.datetime.now()
    dtime   = endtime - starttime
    print("\n\n ---------- run time measure: %s \n" % (dtime))

