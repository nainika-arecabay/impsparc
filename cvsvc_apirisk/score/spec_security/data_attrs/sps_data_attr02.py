from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecDataAttr02(ScoreNode):

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

        self.fix_template = '[CVSPD002] [%s]: Parameters of type "integer" '\
                            'should have format defined.'

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
        return 'sps-data-attr02'

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

        for param_node in self.qspec.get_param_objs():
            param_type = '%s -> type' % param_node
            if self.qspec.G.has_successor(param_node, param_type):
                param_type_integer = '%s -> integer' % param_type
                if self.qspec.G.has_successor(param_type, param_type_integer):
                    param_format = '%s -> format' % param_node
                    if not self.qspec.G.has_successor(param_node, param_format):
                        score = 1
                        remed_clues.append(self.fix_template % param_node)

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
