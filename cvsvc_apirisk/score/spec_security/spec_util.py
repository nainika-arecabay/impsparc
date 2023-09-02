

PATH_OPS_v2 = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch']

class SpecUtil:
    def __init__(self):
        pass


    def get_method_objs(self, spec):
        #import pdb;pdb.set_trace()
        if 'paths' not in spec:
            return {}
        else:
            method_node_names = {}
            for path, indata in spec['paths'].items():
                if path == 'cvlrange26uel7Ao' or path.startswith("__line__"):
                    continue
                try:
                    for method in indata.keys():
                        if method in PATH_OPS_v2:
                            if method in method_node_names:
                                method_node_names[method] = method_node_names[method] + 1
                            else:
                                method_node_names[method] = 1
                except:
                    import pdb;pdb.set_trace()

            return method_node_names


    def get_response_objs(self, spec):
        if 'paths' not in spec:
            return {}
        else:
            response_node_names = {}
            for path, indata in spec['paths'].items():
                if path == 'cvlrange26uel7Ao'  or path.startswith("__line__"):
                    continue
                for method in indata.keys():
                    if method in PATH_OPS_v2:
                        if 'responses' in indata[method]:
                            for responses in indata[method]['responses']:
                                if responses == 'cvlrange26uel7Ao' or responses.startswith("__line__"):
                                    continue
                                if responses in response_node_names:
                                    response_node_names[responses] = response_node_names[responses] + 1
                                else:
                                    response_node_names[responses] = 1

            return response_node_names


    def get_param_objs(self, spec):
        #import pdb;pdb.set_trace()
        #print(spec['openapi'])
        if 'openapi' in spec:
            self.openapi_ver = 'v3'
        else:
            self.openapi_ver = 'v2'
        if 'paths' not in spec:
            return 0, {}, 0
        else:
            data_types = {}
            num_params = 0
            num_apis = 0
            ref_parameter = []
            for path, indata in spec['paths'].items():
                if path == 'cvlrange26uel7Ao'  or path.startswith("__line__"):
                    continue
                num_apis = num_apis +1
                for method in indata.keys():
                    if method in PATH_OPS_v2:
                        if 'parameters' in indata[method]:
                            for parameter in indata[method]['parameters']:
                                if self.openapi_ver == 'v3':
                                    if 'schema' in parameter:
                                        if '$ref' in parameter['schema']:
                                            if isinstance(parameter['schema']['$ref'], str):
                                                ref_parameter.append(parameter['schema']['$ref'])
                                            else:
                                                ref_parameter.append(parameter['schema']['$ref'][0])
                                            #ref_parameter = ref_parameter.append(parameter['schema']['$ref'])
                                        if 'type' in parameter['schema']:
                                            num_params = num_params + 1
                                            p_type = parameter['schema']['type'][0]
                                            #import pdb;pdb.set_trace()
                                            if p_type in data_types:
                                                data_types[p_type] = data_types[p_type] + 1
                                            else:
                                                data_types[p_type] = 1

                                elif self.openapi_ver == 'v2':
                                    if 'schema' in parameter:
                                        parameter = parameter['schema']
                                    if '$ref' in parameter:
                                        if isinstance(parameter['$ref'], str):
                                            ref_parameter.append(parameter['$ref'])
                                        else:
                                            ref_parameter.append(parameter['$ref'][0])

                                    if 'type' in parameter:
                                        num_params = num_params + 1
                                        p_type = parameter['type']
                                        if not isinstance(p_type, str):
                                            p_type = parameter['type'][0]
                                        if p_type in data_types:
                                            data_types[p_type] = data_types[p_type] + 1
                                        else:
                                            data_types[p_type] = 1


            print(data_types)

            #import pdb;pdb.set_trace()
            for ref_data in ref_parameter:
                spec_data = spec
                for data in ref_data.split("/"):
                    if data == '#':
                        continue
                    else:
                        #print(data)
                        spec_data = spec_data.get(data, {})

                if 'type' in spec_data:
                    num_params = num_params + 1
                    p_type = spec_data['type']
                    if not isinstance(p_type, str):
                        p_type = spec_data['type'][0]
                    if p_type in data_types:
                        data_types[p_type] = data_types[p_type] + 1
                    else:
                        data_types[p_type] = 1

            print(data_types)
            return num_params, data_types, num_apis


    def get_all_voilations(self, report, abs_path):
        all_voilations = []
        for data in ['apis', '$refs']:
            for api_path, voilation_key in report['files'][abs_path][data].items():
                for voilations in voilation_key['violations']:
                    all_voilations.append(voilations)

        report['files'][abs_path]['violations'] = all_voilations

        #print(all_voilations)







