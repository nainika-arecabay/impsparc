#-------------------------------------------
#
# s2test_main
#   The main test run that will read rule
#   and a spec file in either json or yaml.
#
#   Perform a spec parse into a tree of SpecNodes.
#
#   The parse rules. Then take the set of rules to
#    find matches in a tree. Collecting violations
#    along the way.
#
#------------------------------------------

import os
import json
import operator
import yaml
import sys
from datetime import datetime

from json_line import SaveLineRangeDecoder
from yaml_line import LineLoader as YamlLineLoader
from spec_util import SpecUtil

from jinja2 import Environment, FileSystemLoader
from spec_parse import SpecTree

from collections import Counter

from rules_util import RuleSet
from rules_util import MatchSet
from sparc_html_generation import Report_Generation

class Impsparc:
    def __init__(self):
        self.matchsets = []
        self.rules = {}
        self.globalvs = []
        self.perapivios = {}
        self.refvios = {}
        self.num_evaluations = 0
        pass

    def load_spec_file(self, inputfname):
        #import pdb;pdb.set_trace()
        with open(inputfname, encoding='utf8') as f:
            if inputfname.endswith(".json"):
                #raw_spec = json.load(f)
                indata = json.load(f, cls=SaveLineRangeDecoder)
            elif inputfname.endswith(".yaml"):
                raw_spec = yaml.safe_load(f)
                f.seek(0)
                loader = YamlLineLoader(f)
                indata = loader.get_single_data()
            else:
                print (" file must be json or yaml... to raise exception.")
                exit()

            spectree = SpecTree(indata)
            spectree.resolveRefs()
            spectree.cleanupAfterRefResolve()
            f.close()

        return spectree

    def load_rules_file(self, rulesfname):
        with open(rulesfname, encoding='utf8') as f:
            if rulesfname.endswith(".json"):
                indata = json.load(f)
            else:
                print (" rule file must be json to raise exception.")
                exit()

            for r in indata["rules"] :
                rdef = RuleSet(r)
                if not rdef.toIgnore:
                    self.rules[rdef.id] = rdef

            for k, r in self.rules.items():
                self.matchsets.append(MatchSet(r))
                # r.printSelf()

            f.close()

        return indata

    def rules_matching(self, spectree, indata):
        print("---- Starting match test against %i rules, global list:\n" % len(self.matchsets))

        for m in self.matchsets:
            self.num_evaluations = self.num_evaluations + m.performGlobalMatches(spectree.nonapinodes, self.globalvs, indata)

        apimatchsets = []
        for mset in self.matchsets :
            if not mset.allMatchGlobal :
                apimatchsets.append(mset)
        print("---- Starting match test against %i rules, api list:\n" % len(apimatchsets))

        for apidef, apinodes in spectree.perapinodes.items() :
            newmsets = []
            for mset in apimatchsets:
                newmset = MatchSet()
                newmset.copyMatch(mset)
                newmsets.append(newmset)

            #print("------ > Checking api=\'%s\', %s nodes ----> \n" % (apidef, len(apinodes)))
            perapiv = []
            for mset in newmsets :
                self.num_evaluations = self.num_evaluations + mset.performPerAPIMatches(apidef, apinodes, perapiv, indata)
            self.perapivios[inputfname+":"+apidef]=perapiv

        refmatchsets = []
        for mset in self.matchsets :
            if not mset.allMatchGlobal :
                refmatchsets.append(mset)
        print("---- Starting match test against %i rules against nodes referenced by APIs:\n" % len(apimatchsets))

        for ref, refnodes in spectree.targetrefnodes.items() :
            newmsets = []
            for mset in refmatchsets:
                newmset = MatchSet()
                newmset.copyMatch(mset)
                newmsets.append(newmset)

            #print("------ > Checking $ref=\'%s\', %i nodes ----> \n" % (ref, len(refnodes)))
            perrefv = []
            for mset in newmsets :
                self.num_evaluations = self.num_evaluations + mset.performRefMatches(ref, refnodes, perrefv, indata)
            self.refvios[inputfname+":"+ref]=perrefv

    def get_properties_voilations(self, report, abs_path, target_obj):
        spec_util_obj = SpecUtil()
        spec_util_obj.get_all_voilations(report, abs_path)


        report['files'][abs_path]['properties']['status'] = 'valid'
        report['files'][abs_path]['properties']['score'] = 9
        #report['files'][abs_path]['properties']['meta'] = spec_main.meta
        # report['files'][abs_path]['properties']['num_apis'] = \
        #     100
        #import pdb;pdb.set_trace()
        report['files'][abs_path]['properties']['version'] = \
            target_obj['info']['version']
        report['files'][abs_path]['properties']['num_evaluations'] = \
            self.num_evaluations


    def get_voilations(self, outputjson, abs_path):
        apir = outputjson["files"][inputfname]["apis"]
        refr = outputjson["files"][inputfname]["$refs"]
        nvios = 0
        for v in self.globalvs:
            apiname = inputfname+": All APIs (Global Definitions)"
            apivs = []
            if not apiname in apir:
                apir[apiname] = {"violations":apivs}
            else:
                apivs = apir[apiname]["violations"]
            nvios += 1
            apivs.append(v.dictR)

        for apiname, vs in self.perapivios.items():
            for v in vs:
                apivs = []
                if not apiname in apir:
                    apir[apiname] = {"violations":apivs}
                else:
                    apivs = apir[apiname]["violations"]
                nvios += 1
                apivs.append(v.dictR)

        for refroot, vs in self.refvios.items():
            for v in vs:
                refstr  = v.vionode.pathstr
                refvs = []
                if not refstr in refr:
                    refr[refstr] = {"violations":refvs}
                else:
                    refvs = refr[refstr]["violations"]
                nvios += 1
                refvs.append(v.dictR)

        return nvios


    def content_count(self, report, abs_path, spec):

        spec_util_obj = SpecUtil()
        #spec_util_obj.get_all_voilations(report, abs_path)
        report['files'][abs_path]['req_method'] = spec_util_obj.get_method_objs(spec)
        report['files'][abs_path]['response_codes'] = spec_util_obj.get_response_objs(spec)

        node_len, data_types_len, num_apis = spec_util_obj.get_param_objs(spec)
        report['files'][abs_path]['data_types'] = data_types_len
        print(node_len)
        report['files'][abs_path]['properties']['num_params'] = node_len
        report['files'][abs_path]['properties']['num_apis'] = num_apis


    def high_level_info(self, report):
        #print_heading('Basic information')

        ## High level info
        print(('* Zip file name:\t%s' % report['file_name']).expandtabs(80))
        #print(('* Zip file uploaded on:\t%s' % report['file_modified_time']).expandtabs(80))
        report['num_appsvcs'] = len(report['files'])

        total_files = 0
        total_apis = 0
        total_params = 0
        total_violations = 0
        total_evaluations = 0
        for f in report['files']:
            if report['files'][f]['properties']['status'] == 'err':
                continue
            total_files += 1
            total_apis += report['files'][f]['properties']['num_apis']
            total_params += report['files'][f]['properties']['num_params']
            total_violations += len(report['files'][f]['violations'])
            total_evaluations += report['files'][f]['properties']['num_evaluations']

        print(('* Total number of application services:\t%d' %
               total_files).expandtabs(80))
        report['total_apis'] = total_apis
        print(('* Total number of APIs observed across all services:\t%d' %
               report['total_apis']).expandtabs(80))

        # print(('* Total number of Parameters observed across all services:\t%d' %
        #       total_params).expandtabs(80))

        print(('* Total number of violations across all services:\t%d (out of'
               ' %d checks)' %
               (total_violations, total_evaluations)).expandtabs(80))
        report['pdf']['page1']['sec4'] = {}
        report['pdf']['page1']['sec4']['total_violations'] = total_violations
        report['pdf']['page1']['sec4']['total_evaluations'] = total_evaluations

        # Top 5 apps by APIs
        print('* Top 5 application services by num APIs')
        # return report
        data = sorted({k: v['num_apis'] for k, v in report['files'].items() \
                       if 'num_apis' in v}.items(),
                      key=operator.itemgetter(1), reverse=True)
        for filename, num_apis in data[:5]:
            print(('    %s\t%d' % (filename.split('/')[-1], num_apis)).expandtabs(40))

        return

    def write_pdf_json(self, report, output_json, cvrules_path, report_obj):
        # Page 1 data

        # Page 1: Section 1
        report['pdf']['page1']['sec1'] = {}
        now = datetime.now()
        report['pdf']['page1']['sec1']['today'] = \
            datetime.strftime(now, '%a, %B %d, %Y')
        report['pdf']['page1']['sec1']['file_name'] = \
            report['file_name'].split('/')[-1]
        report['pdf']['page1']['sec1']['max_risk_score'] = report['max_risk']
        report['pdf']['page1']['sec1']['severity'] = \
            0
        report['pdf']['page1']['sec1']['num_appsvcs'] = report['num_appsvcs']
        report['pdf']['page1']['sec1']['total_apis'] = report['total_apis']

        # Page 2 data
        with open(cvrules_path) as inf:
            rules_dict = json.load(inf)
            ruleid2impact = {}
            for rule in rules_dict['rules']:
                ruleid2impact[rule['ruleid']] = rule.get('impact', None)

        report['pdf']['page2'] = {}

        sev_ctr = Counter()
        absent_impacts = set()
        for f in report['files']:
            for v in report['files'][f]['violations']:
                #try:
                api = report_obj.api_fn(v['v_entity']) or 'Global'
                sev = v['v_severity']
                desc = v['v_description']
                if sev not in report['pdf']['page2']:
                    report['pdf']['page2'][sev] = {}
                if desc not in report['pdf']['page2'][sev]:
                    report['pdf']['page2'][sev][desc] = {}
                    report['pdf']['page2'][sev][desc]['Impact'] = None
                    report['pdf']['page2'][sev][desc]['Count'] = []

                # Add the impact
                impact = ruleid2impact[v['v_ruleid']]
                if impact is None:
                    absent_impacts.add(desc)
                report['pdf']['page2'][sev][desc]['Impact'] = impact

                # Add the formatted violation
                vstr = '%s\n\n%s' % (api, v['v_entity'])
                report['pdf']['page2'][sev][desc]['Count'].append(vstr)

                sev_ctr[sev] += 1

        # Post-process the PDF json
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev not in report['pdf']['page2']:
                continue

            sorted_v = sorted(report['pdf']['page2'][sev].items(),
                              key=lambda x: len(x[1]['Count']), reverse=True)
            sev_key = '%s (%d)' % (sev, sev_ctr[sev])
            report['pdf']['page2'][sev_key] = {}
            for elem in sorted_v:
                report['pdf']['page2'][sev_key][elem[0]] = {}
                report['pdf']['page2'][sev_key][elem[0]]['Impact'] = elem[1]['Impact']
                count_key = 'Count (%d)' % len(elem[1]['Count'])
                report['pdf']['page2'][sev_key][elem[0]][count_key] = elem[1]['Count']

            # Finally drop the original key
            report['pdf']['page2'].pop(sev)

        if output_json is not None:
            # Write the data structure
            with open(output_json, 'w') as outf:
                json.dump(report, outf, indent=1)
        return


if __name__ == '__main__':

    usagestr = "\n Usage: python3 s2test_main.py spec_file_name rule_file_name report_file_name\n"

    if (len(sys.argv) == 4):
        inputfname = sys.argv[1]
        rulesfname = sys.argv[2]
        reportfname = sys.argv[3]
    else:
        print(usagestr)
        exit()

    if not os.path.exists(inputfname):
        print(" Original IMPSpARC JSON report file \"%s\" not found " % (inputfname))
        exit()

    starttime = datetime.now()

    impsparc_obj = Impsparc()

    spectree = impsparc_obj.load_spec_file(inputfname)
    indata = impsparc_obj.load_rules_file(rulesfname)
    impsparc_obj.rules_matching(spectree, indata)

    report = {"file_name": inputfname, "files": {inputfname: {"apis": {}, "$refs": {}}}}
    report['pdf'] = {}
    report['pdf']['page1'] = {}

    report['files'][inputfname]['properties'] = {}
    impsparc_obj.content_count(report, inputfname, spectree.spec)
    nvios = impsparc_obj.get_voilations(report, inputfname)
    impsparc_obj.get_properties_voilations(report, inputfname, spectree.spec)
    impsparc_obj.high_level_info(report)
    #report['total_apis'] = 100

    report_gen = Report_Generation(indata)
    report_gen.analyze_apps(report)
    print('-' * 100)
    report_gen.analyze_apis(report)

    with open(reportfname, 'w', encoding='utf-8') as jfout:
        json.dump(report, jfout, indent=1)
        jfout.close()

    impsparc_obj.write_pdf_json(report, reportfname, rulesfname, report_gen)

    report_gen.generate_html_new(report, reportfname)
    #impsparc_obj.write_html_report(outputjson)

    print("\n\n ---------- Total number of violations: %i \n" % (nvios))
        
    endtime = datetime.now()
    dtime   = endtime - starttime
    print("\n\n ---------- run time measure: %s \n" % (dtime))

