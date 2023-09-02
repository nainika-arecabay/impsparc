from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecDataAttr01(ScoreNode):

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

        self.fix_template = '[CVSPD001] [%s]: Items of type "integer" '\
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
        return 'sps-data-attr01'

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

        for item_node in self.qspec.get_item_objs():
            item_type = '%s -> type' % item_node
            if self.qspec.G.has_successor(item_node, item_type):
                item_type_integer = '%s -> integer' % item_type
                if self.qspec.G.has_successor(item_type, item_type_integer):
                    item_format = '%s -> format' % item_node
                    if not self.qspec.G.has_successor(item_node, item_format):
                        score = 1
                        remed_clues.append(self.fix_template % item_node)

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
