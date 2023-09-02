from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecFormatAttr01(ScoreNode):

    def __init__(self, qspec, target_obj=None, attr_wt=4):
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

        self.fix_template = '[CVSPF001] [%s]: Response codes should '\
                            'be in 200-599.'

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
        return 'sps-fmt-attr01'

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

        for op_node in self.qspec.get_op_objs():
            responses_node = '%s -> responses' % op_node
            for rsp_code_node in self.qspec.G.neighbors(responses_node):
                rsp_code = self.qspec.G.nodes[rsp_code_node]['nodenameraw']
                if rsp_code == 'default':
                    continue
                if not (200 <= int(rsp_code) <= 599):
                    score = 1
                    remed_clues.append(self.fix_template % rsp_code_node)

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
