from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecFormatAttr03(ScoreNode):

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

        self.fix_template = '[CVSPF003] [%s]: Parameters of type != '\
                            '"array" should not have "items" defined.'

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
        return 'sps-fmt-attr03'

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

        for param_idx_node in self.qspec.get_param_objs():
            type_node = '%s -> type' % param_idx_node
            if self.qspec.G.has_node(type_node):
                type_val_node = list(self.qspec.G.neighbors(type_node))[0]
                type_val = self.qspec.G.nodes[type_val_node]['nodenameraw']

                if type_val != 'array':
                    items_node = '%s -> items' % param_idx_node
                    if self.qspec.G.has_node(items_node):
                        score = 1
                        remed_clues.append(self.fix_template % param_idx_node)

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
