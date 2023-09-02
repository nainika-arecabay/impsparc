#-------------------------------------------
#
# sp2_reporting
#
# Contain utilities to hold violations
#  
#
#------------------------------------------

import os
import json
import yaml
import sys


class Violation():
    def __init__(self, ruleobj, node, node_api, apiDef="", apiNode=None):
        #import pdb;pdb.set_trace()
        self.vionode = node
        self.dictR = {}
        self.dictR["v_ruleid"] = ruleobj.info["ruleid"]
        self.dictR["v_description"] = ruleobj.info["description"]
        self.dictR["v_severity"] = self.get_severity(ruleobj.info["score"])
        self.dictR["v_score"] = ruleobj.info["score"]
        self.dictR["v_risk_ctg"] = ruleobj.info["category"]
        self.dictR["v_risk_subctg"] = ruleobj.info["sub_category"]
        self.dictR["v_entity"] = {"reference_path": node_api}
        if node and node.lineNums :  # currently a node's line number is a tuple
            (ln1, ln2) = node.lineNums
            self.dictR["v_entity"]["element_line_num"]=[ln2, ln2]

    def get_severity(self, score):
        if 9 <= score <= 10:
            return 'Critical'
        elif 6 <= score <= 8:
            return 'High'
        elif 4 <= score <= 5:
            return 'Medium'
        elif 1 <= score <= 3:
            return 'Low'
        elif score == 0:
            return 'NoRisk'

        return 'Invalid'

    def get_entity_data(self):
        raw_rule = []
        for meta_data in meta:
            line_num = self.parse_cvlrange(
                self.linenum_mapping,
                meta_data,
                abs_path=abs_path)

            int_line_num = None
            if line_num not in {'', None}:
                int_line_num = json.loads(line_num)
                int_line_num = int_line_num[0]

            intm_raw_rule = {'reference_path': meta_data}
            if int_line_num is not None:
                intm_raw_rule['element_line_num'] = [int_line_num]

            raw_rule.append(intm_raw_rule)

    def parse_cvlrange(linenum_mapping, target_node, ret_cvlrangeds=False, abs_path=None):

        if linenum_mapping is None:
            return ''

        yaml_flag = False
        if abs_path is not None and abs_path.endswith('.yaml'):
            yaml_flag = True
        line_no = ''
        try:
            target_node = re.sub(r'__key__$', '', target_node)
            cvlrange_ds = None  # cvlrange data structure
            nodes = target_node.split('->')
            level = 0

            while level < len(nodes):

                node = nodes[level]

                if level == 0 and node != '#':
                    raise ValueError('[01] Problem while identifying line num for'
                                     'target %s...' % target_node)

                if level == 0:
                    cvlrange_ds = linenum_mapping
                    level += 1
                    continue

                try:
                    if yaml_flag:
                        if type(cvlrange_ds) == list:
                            cvlrange_ds, line_no = cvlrange_ds[int(node)], line_no
                        else:
                            cvlrange_ds, line_no = cvlrange_ds[node], cvlrange_ds[f'__line__{node}']
                    else:
                        if type(cvlrange_ds) == list:
                            cvlrange_ds = cvlrange_ds[int(node)]
                        else:
                            cvlrange_ds = cvlrange_ds[node]
                except KeyError:
                    if '$ref' in cvlrange_ds:
                        # The key error could be because the spec points to another
                        # ref
                        if yaml_flag:
                            ref_str = cvlrange_ds['$ref'].replace('/', '->')
                        else:
                            ref_str = cvlrange_ds['$ref'][0].replace('/', '->')
                        cvlrange_ds, line_no = parse_cvlrange(linenum_mapping, ref_str,
                                                              ret_cvlrangeds=True, abs_path=abs_path)
                        continue
                    else:
                        # If node not present, pass so that the line num of
                        # parent gets returned
                        pass

                level += 1

            if ret_cvlrangeds:
                return cvlrange_ds, line_no

            if yaml_flag:
                try:
                    line_num = '[%d]' % cvlrange_ds[f'__line__{nodes[-1]}']
                except:
                    line_num = line_no
            else:
                if type(cvlrange_ds) == dict:
                    line_num = cvlrange_ds['cvlrange26uel7Ao'][0]
                else:
                    line_num = cvlrange_ds[-1]['cvlrange26uel7Ao'][0]

            linenum_idstr = '[%d]' % line_num
        except:
            linenum_idstr = ''

        return linenum_idstr

    def write_json(report, output_json):
        # Repurpose the "report" data structure
        for f in report['files']:

            report['files'][f]['properties'] = {}
            if report['files'][f]['status'] == 'err':
                report['files'][f]['properties']['status'] = \
                    report['files'][f].pop('status')
                report['files'][f]['properties']['err_detail'] = \
                    report['files'][f].pop('meta')
                report['files'][f]['violations'] = []
            else:
                # Rename the "meta" key to "violations"
                report['files'][f]['violations'] = report['files'][f].pop('meta')
                # Bring file properties together
                report['files'][f]['properties'] = {}
                report['files'][f]['properties']['score'] = \
                    report['files'][f].pop('score')
                report['files'][f]['properties']['status'] = \
                    report['files'][f].pop('status')
                report['files'][f]['properties']['num_apis'] = \
                    report['files'][f].pop('num_apis')
                report['files'][f]['properties']['num_params'] = \
                    report['files'][f].pop('num_params')
                report['files'][f]['properties']['num_evaluations'] = \
                    report['files'][f].pop('num_evaluations')
                report['files'][f]['properties']['version'] = \
                    report['files'][f].pop('version')

                for api in report['files'][f]['apis']:
                    report['files'][f]['apis'][api]['violations'] = \
                        report['files'][f]['apis'][api].pop('meta')

        if output_json is not None:
            # Write the data structure
            with open(output_json, 'w') as outf:
                json.dump(report, outf, indent=1)

        return


    

