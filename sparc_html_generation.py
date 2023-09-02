
import os
from datetime import datetime
import shutil
import hashlib
import  json
import re
import operator
from collections import Counter

from jinja2 import Environment, FileSystemLoader

RISK_CTGS = {
    'Security': 0,
    'Data': 1,
    'Format': 2
}

RISK_SUBCTGS = {
    'Security': {
        'Authentication': 0,
        'Authorization': 1,
        'Transport': 2
    },
    'Data': {},
    'Format': {}
}

SEVERITY_CTGS = {
    'Critical': 0,
    'High': 1,
    'Medium': 2,
    'Low': 3,
    'NoRisk': 4
}


class Report_Generation:

    def __init__(self, rule_exps):
        global RISK_CTGS, RISK_SUBCTGS

        RISK_CTGS, RISK_SUBCTGS = self.init_rules_ds(rule_exps)
        pass

    def init_rules_ds(self, rule_exps):
        # print(rule_exps)

        RISK_CTGS = {}
        RISK_SUBCTGS = {}
        for rule in rule_exps['rules']:
            ctg = rule['category']
            sub_ctg = rule['sub_category']

            # Categories
            if ctg not in RISK_CTGS:
                idx = len(RISK_CTGS)
                RISK_CTGS[ctg] = idx

            # Sub-categories
            if ctg not in RISK_SUBCTGS:
                RISK_SUBCTGS[ctg] = {}
            if sub_ctg not in RISK_SUBCTGS[ctg]:
                idx = len(RISK_SUBCTGS[ctg])
                RISK_SUBCTGS[ctg][sub_ctg] = idx

        return RISK_CTGS, RISK_SUBCTGS

    def compute_violation_counts(self, report):
        """
        {
            'most_occ_cat_count': 2,
            'most_occ_cat': 'Undefined Bounds',
            'description': 'properties of type "array" should have "maxItems" defined.',
            'API Lifecycle & Management': {
                'risk_sub_ctg': {
                    'Missing information': 1
                },
                'total_count': 1,
                'highest_sev': 'Low',
                'Low': 1,
                'highest_sev_count': 1
            },
            'Data Type Definitions': {
                'risk_sub_ctg': {
                'Undefined Bounds': 2
                },
                'total_count': 2,
                'highest_sev': 'High',
                'High': 2,
                'highest_sev_count': 2
            },
            'risk_siv_counts': {
                'critical': 0,
                'high': 2,
                'medium': 0,
                'low': 1
            }
        }
        """
        violation_counts = {}
        risk_siv_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        for key, value in report.get('files', {}).items():
            violations = value.get('violations', [])
            for each_violation in violations:
                severity = each_violation.get('v_severity')
                risk_ctg = each_violation.get('v_risk_ctg')
                risk_sub_ctg = each_violation.get('v_risk_subctg')
                description = each_violation.get('v_description')
                entity = each_violation.get('v_entity')
                risk_ctg_counts = {
                    'risk_sub_ctg': {}
                }
                risk_siv_counts[severity.lower()] += 1

                highest_sev = None
                if risk_ctg in violation_counts:
                    risk_ctg_counts = violation_counts[risk_ctg]

                    if risk_sub_ctg in risk_ctg_counts.get('risk_sub_ctg', {}):
                        risk_ctg_counts['risk_sub_ctg'][risk_sub_ctg] += 1
                    else:
                        risk_ctg_counts['risk_sub_ctg'][risk_sub_ctg] = 1

                    if severity in risk_ctg_counts:
                        risk_ctg_counts[severity] += 1
                    else:
                        risk_ctg_counts[severity] = 1

                    if 'total_count' in risk_ctg_counts:
                        risk_ctg_counts['total_count'] += 1
                    else:
                        risk_ctg_counts['total_count'] = 1

                    if 'highest_sev' in risk_ctg_counts:
                        highest_sev = risk_ctg_counts['highest_sev']
                        if highest_sev.lower() == 'critical':
                            continue
                        elif highest_sev.lower() == 'high' and severity.lower() == 'critical':
                            highest_sev = severity
                        elif highest_sev.lower() == 'medium' and severity.lower() in ['critical', 'high']:
                            highest_sev = severity
                        elif highest_sev.lower() == 'low' and severity.lower() in ['critical', 'high', 'medium']:
                            highest_sev = severity
                        risk_ctg_counts['highest_sev'] = highest_sev
                    else:
                        risk_ctg_counts['highest_sev'] = severity
                else:
                    highest_sev = severity
                    risk_ctg_counts['total_count'] = 1
                    risk_ctg_counts['highest_sev'] = severity
                    risk_ctg_counts[severity] = 1
                    risk_ctg_counts['risk_sub_ctg'][risk_sub_ctg] = 1

                most_occ_cat = violation_counts.get('most_occ_cat', '')
                most_occ_cat_count = violation_counts.get('most_occ_cat_count', 0)
                if risk_ctg_counts['risk_sub_ctg'][risk_sub_ctg] > most_occ_cat_count:
                    violation_counts['most_occ_cat_count'] = risk_ctg_counts['risk_sub_ctg'][risk_sub_ctg]
                    violation_counts['most_occ_cat'] = risk_sub_ctg
                    violation_counts['description'] = description

                violation_counts[risk_ctg] = risk_ctg_counts

        violation_counts['risk_siv_counts'] = risk_siv_counts
        for k, v in violation_counts.items():
            if not isinstance(violation_counts[k], dict): continue
            if 'highest_sev' not in violation_counts[k]:
                continue
            sev = violation_counts[k]['highest_sev']
            param_count, api_count = self.get_highest_sev_params_api_count(report, sev, k)
            violation_counts[k]['highest_sev_param_count'] = param_count
            violation_counts[k]['highest_sev_api_count'] = api_count
            violation_counts[k]['highest_sev_count'] = violation_counts[k][sev]
        return violation_counts

    def get_highest_sev_params_api_count(self, report, sev, ctg):
        param_list = set()
        api_list = set()
        files = report.get('files', {})
        for file_name, val in files.items():
            apis = val.get('apis', {})
            for api, api_val in apis.items():
                violations = api_val.get('violations', [])
                for violation in violations:
                    entity = violation.get('v_entity', '')
                    if violation.get('v_severity', '') == sev and violation.get('v_risk_ctg', '') == ctg:
                        if self.contains_param(entity):
                            param_list.add(self.get_param_from_entity(entity))
                        api_list.add(api)
        return len(param_list), len(api_list)

    def analyze_apps(self, report):
        #print_heading('App analysis')

        report['pdf']['page1']['sec2'] = {}

        ## Top-level app insights
        # Risk defined across all services
        risk_scores = [report['files'][f]['score'] for f in report['files'] \
                       if 'score' in report['files'][f]]
        report['max_risk'] = max(risk_scores) if len(risk_scores) > 0 else 0
        print(('* Max risk across all application services:\t%d (%s)' %
               (report['max_risk'], self.get_severity(report['max_risk']))).expandtabs(20))

        # Risk statistics
        report['avg_risk'] = round(np.mean(risk_scores), 2) if len(risk_scores) > 0 else 0
        print(('* Average risk across all application services:\t%d' %
               report['avg_risk']).expandtabs(20))

        num_nz_risk = len(list(filter(lambda x: x > 0, risk_scores)))
        print(('* Number of application services with non-zero risk:\t%d' %
               num_nz_risk).expandtabs(20))
        num_z_risk = len(list(filter(lambda x: x == 0, risk_scores)))
        print(('* Number of application services with zero risk:\t%d' %
               num_z_risk).expandtabs(20))

        # Initialize the data structure
        report['pdf']['page1']['sec2']['2a'] = {}

        severities = []
        file_severities = []
        for f in report['files']:
            #if report['files'][f]['status'] == 'err':
            #    continue
            severities.append(self.get_severity(report['files'][f]['properties']['score']))
            file_severities.append((f, report['files'][f]['properties']['score']))
        print('* Number of application services by Severity:')
        # for k, v in Counter(severities).items():
        ctr = Counter(severities)
        for k in SEVERITY_CTGS:
            print(('\t%s\t%d' % (k, ctr[k])).expandtabs(10))
            report['pdf']['page1']['sec2']['2a'][k] = ctr[k]

        print('* Top 5 application services ranked by Severity:')
        for f, score in sorted(file_severities, key=operator.itemgetter(1),
                               reverse=True)[:5]:
            print(('    %s\t%s' % (f.split('/')[-1],
                                   self.get_severity(score))).expandtabs(20))

        app_severity_riskctg = {}
        app_severity_risksubctg = {}
        ## Severity/Category-based app insights
        for f in report['files']:
            if report['files'][f]['properties']['status'] == 'err':
                continue

            if f not in app_severity_riskctg:
                app_severity_riskctg[f] = {}
                app_severity_risksubctg[f] = {}

            # for attr_score, remed_clue in report['files'][f]['meta']:
            for v in report['files'][f]['violations']:
                severity = self.get_severity(v['v_score'])

                if severity not in app_severity_riskctg[f]:
                    app_severity_riskctg[f][severity] = {}
                    app_severity_risksubctg[f][severity] = {}

                risk_ctg, risk_subctg = v['v_risk_ctg'], v['v_risk_subctg']
                if risk_ctg not in app_severity_riskctg[f][severity]:
                    app_severity_riskctg[f][severity][risk_ctg] = 0
                    app_severity_risksubctg[f][severity][risk_ctg] = {}

                # Log the violation
                app_severity_riskctg[f][severity][risk_ctg] += 1

                if risk_subctg is not None:
                    if risk_subctg not in \
                            app_severity_risksubctg[f][severity][risk_ctg]:
                        app_severity_risksubctg[f][severity][risk_ctg][risk_subctg] = 0
                    app_severity_risksubctg[f][severity][risk_ctg][risk_subctg] += 1

            # report['app_severity_riskctg'] = app_severity_riskctg

        print('* Number of application services by RiskCategory-Severity:')
        severity_ctg_cnts = {}
        for f in app_severity_riskctg:
            for severity in app_severity_riskctg[f]:
                if severity not in severity_ctg_cnts:
                    severity_ctg_cnts[severity] = {}
                for risk_ctg in app_severity_riskctg[f][severity]:
                    if risk_ctg not in severity_ctg_cnts[severity]:
                        severity_ctg_cnts[severity][risk_ctg] = 0
                    severity_ctg_cnts[severity][risk_ctg] += 1

        report['pdf']['page1']['sec2']['2b'] = {}
        # Initialize the data structure
        for sev in SEVERITY_CTGS:
            report['pdf']['page1']['sec2']['2b'][sev] = {}
            for risk in RISK_CTGS or []:
                report['pdf']['page1']['sec2']['2b'][sev][risk] = 0

        # Now print
        for severity in sorted(severity_ctg_cnts, key=lambda s: SEVERITY_CTGS[s]):

            for ctg in sorted(severity_ctg_cnts[severity],
                              key=lambda r: RISK_CTGS[r]):
                print(('    %s\t%s\t%d' % (severity, ctg,
                                           severity_ctg_cnts[severity][ctg])).expandtabs(20))
                report['pdf']['page1']['sec2']['2b'][severity][ctg] = \
                    severity_ctg_cnts[severity][ctg]

    def compute_counts(self, report):
        """
        {
            'num_of_params': 12,
            'num_of_data_types': 1,
            'response_codes': [
                '200',
                'default'
            ],
            'response_codes_count': [
                5,
                5
            ],
            'd_types': [
                'list'
            ],
            'd_type_counts': [
                4
            ],
            'req_method_list': ['GET', 'POST'],
            'req_method_count': [20, 10],
            'num_evaluations': 443
        }
        """

        counts = {
            'num_of_params': 0,
            'num_of_data_types': 0,
            'response_codes': [],
            'response_codes_count': [],
            'd_types': [],
            'd_type_counts': [],
            'req_method_list': [],
            'req_method_count': [],
            'num_evaluations': 0,
        }
        res_codes = {}
        d_types = {}
        request_methods = {}

        files = report.get('files')
        for key, value in files.items():
            if value.get('properties', {}).get('status') == 'err':
                continue
            counts['num_evaluations'] += value.get('properties', {}).get('num_evaluations', 0)
            counts['num_of_params'] += value.get('properties', {}).get('num_params', 0)
            counts['num_of_data_types'] += len(value.get('data_types', []))

            req_methods = value.get('req_method', {})
            for method, req_count in req_methods.items():
                if method in request_methods:
                    request_methods[method] += req_count
                else:
                    request_methods[method] = req_count

            response_codes = value.get('response_codes', {})
            for res_code, r_count in response_codes.items():
                if res_code in res_codes:
                    res_codes[res_code] += r_count
                else:
                    res_codes[res_code] = r_count

            data_types = value.get('data_types', {})
            for d_type, count in data_types.items():
                if d_type in d_types:
                    d_types[d_type] += count
                else:
                    d_types[d_type] = count

        r_codes, r_counts = [], []
        for r_code, r_count in res_codes.items():
            r_codes.append(r_code)
            r_counts.append(r_count)
        counts['response_codes'] = r_codes
        counts['response_codes_count'] = r_counts

        dt_types, dt_counts = [], []
        for d_type, d_count in d_types.items():
            dt_types.append(d_type)
            dt_counts.append(d_count)
        counts['d_types'] = dt_types
        counts['d_type_counts'] = dt_counts

        req_method_list, req_method_count = [], []
        for req_method, req_count in request_methods.items():
            req_method_list.append(req_method.upper())
            req_method_count.append(req_count)
        counts['req_method_list'] = req_method_list
        counts['req_method_count'] = req_method_count

        return counts

    def get_issue_insights(self, report):
        """
        {
            'Data Type Definitions': {
                'Undefined Bounds': {
                    'apis': {
                        'orangebank_user.json:/history'
                    },
                    'files': {
                        'cvapirisk_pkg/orangebank_user.json'
                    },
                    'high': 1
                }
            }
        }
        """
        issue_insights = {}
        files = report.get('files', {})
        for file_name, record in files.items():
            apis = record.get('apis', {})
            for api, val in apis.items():
                violations = val.get('violations', [])
                for each_violation in violations:
                   self.add_violation(issue_insights, each_violation, file_name, api)
            violations = record.get('violations', [])
            for violation in violations:
                self.add_violation(issue_insights, violation, file_name)
        return issue_insights

    def initialise_issue_insights(self, issue_insights, risk_ctg, risk_sub_ctg, i_type):
        issue_insights[risk_ctg][risk_sub_ctg][i_type] = set()
        issue_insights[risk_ctg][risk_sub_ctg]['critical_' + i_type] = set()
        issue_insights[risk_ctg][risk_sub_ctg]['high_' + i_type] = set()
        issue_insights[risk_ctg][risk_sub_ctg]['medium_' + i_type] = set()
        issue_insights[risk_ctg][risk_sub_ctg]['low_' + i_type] = set()

    def add_sev_issue_insights(self, issue_insights, risk_ctg, risk_sub_ctg, i_type, val, severity):
        if not val: return
        issue_insights[risk_ctg][risk_sub_ctg][i_type].add(val)
        if severity == 'critical':
            issue_insights[risk_ctg][risk_sub_ctg]['critical_' + i_type].add(val)
        elif severity == 'high':
            issue_insights[risk_ctg][risk_sub_ctg]['high_' + i_type].add(val)
        elif severity == 'medium':
            issue_insights[risk_ctg][risk_sub_ctg]['medium_' + i_type].add(val)
        else:
            issue_insights[risk_ctg][risk_sub_ctg]['low_' + i_type].add(val)

    def add_violation(self, issue_insights, violation, file_name, api=''):
        violation_hash = hashlib.md5((json.dumps(violation) + file_name).encode()).hexdigest()
        if violation_hash in issue_insights.get('hash_list', set()):
            return
        risk_ctg = violation.get('v_risk_ctg', '')
        risk_sub_ctg = violation.get('v_risk_subctg', '')
        severity = violation.get('v_severity', '').lower()
        entity = violation.get('v_entity', '')
        tags = violation.get('v_tags', '')
        if risk_ctg not in issue_insights:
            issue_insights[risk_ctg] = {}
        if risk_sub_ctg not in issue_insights[risk_ctg]:
            issue_insights[risk_ctg][risk_sub_ctg] = {}
        if 'apis' not in issue_insights[risk_ctg][risk_sub_ctg]:
            self.initialise_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'apis')
        if 'files' not in issue_insights[risk_ctg][risk_sub_ctg]:
            self.initialise_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'files')
        if 'params' not in issue_insights[risk_ctg][risk_sub_ctg]:
            self.initialise_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'params')
        if 'tags' not in issue_insights[risk_ctg][risk_sub_ctg]:
            issue_insights[risk_ctg][risk_sub_ctg]['tags'] = set()
        if severity not in issue_insights[risk_ctg][risk_sub_ctg]:
            issue_insights[risk_ctg][risk_sub_ctg][severity] = 0
        if 'hash_list' not in issue_insights:
            issue_insights['hash_list'] = set()
        if 'param_list' not in issue_insights[risk_ctg]:
            issue_insights[risk_ctg]['param_list'] = set()
        if 'api_list' not in issue_insights[risk_ctg]:
            issue_insights[risk_ctg]['api_list'] = set()
        if 'file_list' not in issue_insights[risk_ctg]:
            issue_insights[risk_ctg]['file_list'] = set()
        issue_insights[risk_ctg][risk_sub_ctg][severity] += 1
        issue_insights['hash_list'].add(violation_hash)
        issue_insights[risk_ctg]['file_list'].add(file_name)
        for tag in tags:
            issue_insights[risk_ctg][risk_sub_ctg]['tags'].add(tag)
        self.add_sev_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'files', file_name, severity)
        if api != '':
            issue_insights[risk_ctg]['api_list'].add(api)
            self.add_sev_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'apis', api, severity)
        if self.contains_param(entity):
            param = self.get_param_from_entity(entity)
            issue_insights[risk_ctg]['param_list'].add(param)
            self.add_sev_issue_insights(issue_insights, risk_ctg, risk_sub_ctg, 'params', param, severity)

    def contains_param(self, entity):
        if isinstance(entity, dict):
            entity = entity['reference_path']
        if entity.startswith('(#->paths') and "parameters->" in entity:
            return True
        return False

    def get_param_from_entity(self, entity):
        param = ''
        if isinstance(entity, dict):
            entity = entity['reference_path']
        start = entity.index('(') + len('(')
        end = entity.index(')', start)
        api_param = entity[start:end]
        split_list = api_param.split('->')
        for i in range(6):
            param = param + '->' + split_list[i]
        return param

    def analyze_apis_riskctg(self, report, api_riskctg_severity):
        report['pdf']['page1']['sec3']['3b'] = {}
        # Initialize the data structure
        for sev in SEVERITY_CTGS:
            report['pdf']['page1']['sec3']['3b'][sev] = {}
            for risk in RISK_CTGS:
                report['pdf']['page1']['sec3']['3b'][sev][risk] = 0

        print('* Number of APIs by RiskCategory-Severity:')
        #for riskctg, severity_dict in api_riskctg_severity.items():
        for riskctg in sorted(api_riskctg_severity, key=lambda r: RISK_CTGS[r]):
            severity_dict = api_riskctg_severity[riskctg]
            # for severity in severity_dict:
            for severity in sorted(severity_dict, key=lambda s: SEVERITY_CTGS[s]):
                print(('    %s\t%s\t%d' % (severity, riskctg,
                                           len(severity_dict[severity]['apis']))).expandtabs(20))
                report['pdf']['page1']['sec3']['3b'][severity][riskctg] = \
                    len(severity_dict[severity]['apis'])

        '''
        report['pdf']['page1']['sec3']['3c'] = {}
        # Initialize the data structure
        for sev in SEVERITY_CTGS:
            report['pdf']['page1']['sec3']['3c'][sev] = {}
            for risk in ['AuthN/AuthZ', 'API Transport']:
                report['pdf']['page1']['sec3']['3c'][sev][risk] = {}
                for subctg in RISK_SUBCTGS[risk]:
                    report['pdf']['page1']['sec3']['3c'][sev][risk][subctg] = 0
        '''

        print('* Number of APIs by RiskCategory-Severity-RiskSubCategory:')
        # for riskctg, severity_dict in api_riskctg_severity.items():
        for riskctg in sorted(api_riskctg_severity, key=lambda r: RISK_CTGS[r]):
            severity_dict = api_riskctg_severity[riskctg]
            # for severity in severity_dict:
            for severity in sorted(severity_dict, key=lambda s: SEVERITY_CTGS[s]):
                for risksubctg, apilist in \
                        severity_dict[severity]['subctgs'].items():
                    print(('    %s\t%s\t%s\t%d' % (severity, riskctg, risksubctg,
                                                   len(apilist))).expandtabs(20))
        '''
                    report['pdf']['page1']['sec3']['3c'][severity][riskctg][risksubctg] = \
                                                 len(apilist)
        '''

        return

    def init_api_ds(self, report, f, api):
        report['files'][f]['apis'][api] = {}
        # report['files'][f]['apis'][api]['severities'] = []
        # report['files'][f]['apis'][api]['risk_ctg'] = []
        # report['files'][f]['apis'][api]['risk_subctg'] = []
        report['files'][f]['apis'][api]['meta'] = []
        return

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

    def api_fn(self, remed_clue):
        if isinstance(remed_clue, str):
            matches = re.findall('\((.*?)\)', remed_clue)
        else:
            matches = re.findall('\((.*?)\)', remed_clue['reference_path'])
        # print(matches)
        for match in matches:
            identifier = match.split(' ')[0]
            if identifier.startswith('#->paths->'):
                api = identifier.split('->')[2]
                return api

        return None

    def analyze_apis(self, report):
        #print_heading('API analysis')

        report['pdf']['page1']['sec3'] = {}

        api_riskctg_severity = {}
        ## Severity/Category-based API insights
        for f in report['files']:
            if report['files'][f]['properties']['status'] == 'err':
                continue

            # for attr_score, remed_clue in report['files'][f]['meta']:

            for v in report['files'][f]['violations']:
                remed_clue = '%s %s %s' % (v['v_ruleid'], v['v_entity'],
                                           v['v_description'])
                api = self.api_fn(remed_clue)
                if api is None:
                    continue
                api = f.split('/')[-1] + ':' + api
                if api not in report['files'][f]['apis']:
                    self.init_api_ds(report, f, api)

                if 'violations' in report['files'][f]['apis'][api]:
                    report['files'][f]['apis'][api]['violations'].append(v)
                else:
                    report['files'][f]['apis'][api]['violations'] = []
                    report['files'][f]['apis'][api]['violations'].append(v)

                severity = self.get_severity(v['v_score'])
                # report['files'][f]['apis'][api]['severities'].append(severity)
                risk_ctg, risk_subctg = v['v_risk_ctg'], v['v_risk_subctg']
                # report['files'][f]['apis'][api]['risk_ctg'].append(risk_ctg)
                # if risk_subctg is not None:
                #    report['files'][f]['apis'][api]['risk_subctg'].append(risk_subctg)

                if risk_ctg not in api_riskctg_severity:
                    api_riskctg_severity[risk_ctg] = {}
                if severity not in api_riskctg_severity[risk_ctg]:
                    api_riskctg_severity[risk_ctg][severity] = {}
                    api_riskctg_severity[risk_ctg][severity]['apis'] = set()
                    api_riskctg_severity[risk_ctg][severity]['subctgs'] = {}
                api_riskctg_severity[risk_ctg][severity]['apis'].add(api)
                if risk_subctg is not None:
                    if (risk_subctg not in
                            api_riskctg_severity[risk_ctg][severity]['subctgs']):
                        api_riskctg_severity[risk_ctg][severity]['subctgs'][risk_subctg] = set()
                    api_riskctg_severity[risk_ctg][severity]['subctgs'][risk_subctg].add(api)

        # analyze_apis_uniq_severity_old(report, api_riskctg_severity)

        self.analyze_apis_uniq_api_new(report, api_riskctg_severity)

        # return api_riskctg_severity

        return

    def analyze_apis_uniq_api_new(self, report, api_riskctg_severity):
        severity_cntr = Counter()
        for f in report['files']:
            if report['files'][f]['properties']['status'] == 'err':
                continue
            for api in report['files'][f]['apis']:
                max_score = max([v['v_score'] for v in \
                                 report['files'][f]['apis'][api]['violations']],
                                default=0)
                max_score_severity = self.get_severity(max_score)
                severity_cntr[max_score_severity] += 1

        report['pdf']['page1']['sec3']['3a'] = {}
        # Initialize the data structure
        for sev in SEVERITY_CTGS:
            report['pdf']['page1']['sec3']['3a'][sev] = 0

        print('* Number of APIs by Severity:')
        for severity in sorted(severity_cntr, key=lambda s: SEVERITY_CTGS[s]):
            print(('    %s\t%d' % (severity, severity_cntr[severity])).expandtabs(20))
            report['pdf']['page1']['sec3']['3a'][severity] = severity_cntr[severity]

        if 'NoRisk' not in severity_cntr:
            total_violated_apis = sum(severity_cntr.values())
            num_norisk_apis = report['total_apis'] - total_violated_apis
            print(('    %s\t%d' % ('NoRisk', num_norisk_apis)).expandtabs(20))
            report['pdf']['page1']['sec3']['3a']['NoRisk'] = num_norisk_apis

        self.analyze_apis_riskctg(report, api_riskctg_severity)

        return

    def copytree(self, src, dst, symlinks=False, ignore=None):
        for item in os.listdir(src):
            try:
                s = os.path.join(src, item)
                d = os.path.join(dst, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, symlinks, ignore)
                else:
                    shutil.copy2(s, d)
            except FileExistsError:
                pass

    def generate_html_new(self, report, output_path, customer_name='N/A'):
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        templates_dir = os.path.join(curr_dir, 'sparc-templates-new')
        output_dir = os.path.join(os.path.dirname(os.path.abspath(output_path)), 'sparc_report')
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Copy css files to output directory
        self.copytree(templates_dir, output_dir, symlinks=True)
        os.remove(os.path.join(output_dir, 'risk-report-template-generic.html'))

        # NOTE: I have deleted index_raw.html from the template folder but for
        # some reason this file is still present on pypi server.
        # TODO: delete next 3 lines when index_raw.html is removed from pypi package
        index_raw = os.path.join(output_dir, 'index_raw.html')
        if os.path.isfile(index_raw):
            os.remove(index_raw)

        html_file = os.path.join(output_dir, 'index.html')
        current_time = datetime.now()
        dt_string = current_time.strftime("%B %d, %Y %H:%M:%S")

        env = Environment(loader=FileSystemLoader(templates_dir))
        template = env.get_template('risk-report-template-generic.html')

        counts = self.compute_counts(report)
        violation_counts = self.compute_violation_counts(report)
        issue_insights = self.get_issue_insights(report)
        violation_details_old = report.get('pdf', {}).get('page2', {})

        violation_details = {'Critical': {}, 'Major': {}, 'Minor': {}}
        for key, value in violation_details_old.items():
            if 'critical' in key.lower() or 'high' in key.lower():
                violation_details['Critical'].update(value)
            elif 'medium' in key.lower():
                violation_details['Major'].update(value)
            elif 'low' in key.lower():
                violation_details['Minor'].update(value)

        with open(html_file, 'w') as fh:
            fh.write(template.render(
                customer_name=customer_name,
                created_time=dt_string,
                file_name=report.get('file_name', 'N/A'),
                num_of_files=len(report.get('files')),
                num_of_apis=report.get('total_apis', 0),
                num_of_params=counts.get('num_of_params', 0),
                num_of_data_types=counts.get('num_of_data_types', 0),
                response_codes=counts.get('response_codes', []),
                r_codes_count=counts.get('response_codes_count', []),
                data_types=counts.get('d_types', []),
                data_type_counts=counts.get('d_type_counts', []),
                req_method_list=counts.get('req_method_list', []),
                req_method_count=counts.get('req_method_count', []),
                violations=violation_counts,
                num_of_evaluations=counts['num_evaluations'] if counts.get('num_evaluations', 0) > 0 else -1,
                issue_insights=issue_insights,
                violation_details=violation_details,
            ))
            fh.close()


