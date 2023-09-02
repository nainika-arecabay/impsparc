from cvsvc_apirisk.score.base import ScoreNode, check_meta


class SpecSecSecurityAttr07(ScoreNode):

    def __init__(self, qspec, openapi_ver, target_obj=None, attr_wt=7):
        """
        Description

        Params
        ------
        p1 : float
            Param description
        p2 : int, optional
            Param description

        Returns
        -------
        result: int
            Result desc
        """
        super().__init__()

        # self.fix_template = \
        #    '[CVSPS107] [%s]: Security scope not in "securityDefinitions".'
        # self.fix_template = {
        #        'ruleid': 'CVSPS100a',
        #        'description': 'Security scope not in "securityDefinitions".'
        #        }

        self.qspec = qspec
        self.openapi_ver = openapi_ver
        self.target_obj = target_obj
        self.attr_wt = attr_wt

    def __repr__(self):
        """
        Description

        Params
        ------
        p1 : float
            Param description
        p2 : int, optional
            Param description

        Returns
        -------
        result: int
            Result desc
        """
        return 'sps-sec-attr07'

    def compute_openapiv2(self):
        """
        Description

        Params
        ------
        p1 : float
            Param description
        p2 : int, optional
            Param description

        Returns
        -------
        result: int
            Result desc
        """
        meta = []
        #import pdb;pdb.set_trace()
        secdefn_node = '%s->securityDefinitions' % self.qspec.ROOT_NODE
        for security_node in self.qspec.get_security_objs():
            for security_idx_node in self.qspec.G.iterNeighbors(self.qspec.node_id_mapping[security_node]):
                for secschm_name_node in self.qspec.G.iterNeighbors(security_idx_node):
                    secschm_name = self.qspec.node_attributes['node_name_raw'][secschm_name_node]
                    for scope_node_idx in self.qspec.G.iterNeighbors(secschm_name_node):
                        for scope_node in self.qspec.G.iterNeighbors(scope_node_idx):
                            scope_name = self.qspec.node_attributes['node_name_raw'][scope_node]
                            target_node = '%s->%s->scopes->%s' % \
                                          (secdefn_node, secschm_name, scope_name)

                            if not self.qspec.G.hasNode(
                                    self.qspec.node_id_mapping.get(target_node, self.qspec.total_node_plus_ten)):
                                # v = self.fix_template.copy()
                                # v['entity'] = scope_node
                                # v['score'] = self.attr_wt
                                # meta.append(v['entity'])
                                meta_node = '%s->%s->%s->%s' % (security_node, self.qspec.node_attributes['node_name_raw'][security_idx_node], secschm_name, self.qspec.node_attributes['node_name_raw'][scope_node_idx])
                                meta.append(meta_node)

        self.score = self.attr_wt * int(len(meta) > 0)
        if len(meta) > 0:
            self.meta = meta

    def compute_openapiv3(self):
        """
        Description

        Params
        ------
        p1 : float
            Param description
        p2 : int, optional
            Param description

        Returns
        -------
        result: int
            Result desc
        """
        meta = []

        all_scopes = set()
        # Collect all defined scopes
        secschms_node = '%s->components->securitySchemes' % self.qspec.ROOT_NODE
        if secschms_node not in self.qspec.node_id_mapping:
            return

        for secschm_node in self.qspec.G.iterNeighbors(self.qspec.node_id_mapping[secschms_node]):
            type_oauth2_node = '%s->type->oauth2' % self.qspec.node_attributes['node_name_sp'][secschm_node]
            if not self.qspec.G.hasNode(
                    self.qspec.node_id_mapping.get(type_oauth2_node, self.qspec.total_node_plus_ten)):
                continue

            oauth_flows_node = '%s->flows' % self.qspec.node_attributes['node_name_sp'][secschm_node]
            for oauth_flow_node in self.qspec.G.iterNeighbors(self.qspec.node_id_mapping[oauth_flows_node]):
                scopes_node = '%s->scopes' % self.qspec.node_attributes['node_name_sp'][oauth_flow_node]
                for scope in self.qspec.G.iterNeighbors(self.qspec.node_id_mapping[scopes_node]):
                    all_scopes.add(self.qspec.node_attributes['node_name_raw'][scope])

        for security_node in self.qspec.get_security_objs():
            for security_idx_node in self.qspec.G.iterNeighbors(self.qspec.node_id_mapping[security_node]):
                for secschm_name_node in self.qspec.G.iterNeighbors(security_idx_node):
                    for scope_node_idx in self.qspec.G.iterNeighbors(secschm_name_node):
                        for scope_node in self.qspec.G.iterNeighbors(scope_node_idx):

                            scope_name = self.qspec.node_attributes['node_name_raw'][scope_node]

                            if scope_name not in all_scopes:
                                # v = self.fix_template.copy()
                                # v['v_entity'] = scope_node
                                # v['v_score'] = self.attr_wt
                                meta.append(scope_node)

        self.score = self.attr_wt * int(len(meta) > 0)
        if len(meta) > 0:
            self.meta = meta

    @check_meta
    def compute(self):
        """
        Description

        Params
        ------
        p1 : float
            Param description
        p2 : int, optional
            Param description

        Returns
        -------
        result: int
            Result desc
        """
        if self.openapi_ver == 'v2':
            self.compute_openapiv2()
        else:
            self.compute_openapiv3()
