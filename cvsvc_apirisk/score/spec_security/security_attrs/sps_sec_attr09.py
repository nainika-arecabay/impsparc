from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecSecurityAttr09(ScoreNode):

    def __init__(self, qspec, target_obj=None, attr_wt=6):
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

        self.fix_template = \
            '[CVSPS209] [%s]: Specify "consumes" field for POST/PUT/PATCH '\
            'operations either globally or locally.'

        self.qspec = qspec
        self.target_obj = target_obj
        self.attr_wt = attr_wt

        return

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
        return 'sps-sec-attr09'

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
        score = 0
        remed_clues = []

        # Check if there is a global "consumes" field
        global_consumes_node = '%s -> consumes' % self.qspec.ROOT_NODE
        has_glb_consumes = self.qspec.G.has_node(global_consumes_node)

        # Check if local "consumes" field
        op_nodes = self.qspec.get_op_objs()
        for op_node in op_nodes:
            op_kind = self.qspec.G.nodes[op_node]['nodenameraw']
            if op_kind.lower() in {'post', 'put', 'patch'}:
                local_consumes_node = '%s -> consumes' % op_node
                if ((not has_glb_consumes) and
                        (not self.qspec.G.has_node(local_consumes_node))):
                    score = 1
                    remed_clues.append(self.fix_template % op_node)

        self.score = self.attr_wt*score
        if self.score > 0:
            self.remed_clue = remed_clues
            self.meta = [(self.attr_wt, x) for x in remed_clues]

        return

    @check_remed
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
        self.compute_openapiv2()
        return
