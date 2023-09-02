from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecSecurityAttr04(ScoreNode):

    def __init__(self, qspec, target_obj=None, attr_wt=9):
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
            '[CVSPS004] [%s]: Global or local "security" field is empty.'

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
        return 'sps-sec-attr04'

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

        # Check global security node
        global_security_node = '%s -> security' % self.qspec.ROOT_NODE
        global_empty = True
        if self.qspec.G.has_node(global_security_node):
            sec_schemes = list(self.qspec.G.neighbors(global_security_node))
            if len(sec_schemes) != 0:
                global_empty = False

        # Check the ops objects where SecurityRequirements exists
        for op_node in self.qspec.get_op_objs():
            local_security_node = '%s -> security' % op_node
            if not self.qspec.G.has_node(local_security_node):
                if global_empty:
                    score = 1
                    remed_clues.append(self.fix_template % op_node)
            else:
                # Local security node is present
                sec_schemes = list(self.qspec.G.neighbors(local_security_node))
                if len(sec_schemes) == 0:
                    score = 1
                    remed_clues.append(self.fix_template % local_security_node)

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
