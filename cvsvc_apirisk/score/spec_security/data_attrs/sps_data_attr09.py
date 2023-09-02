from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecDataAttr09(ScoreNode):

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

        self.fix_template = \
            '[CVSPD009] [%s]: String parameter has no "maxLength" defined.'

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
        return 'sps-data-attr09'

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

        for anode in self.qspec.get_param_objs():
            anode_type = '%s -> type' % anode
            if self.qspec.G.has_successor(anode, anode_type):
                anode_type_string = '%s -> string' % anode_type
                if self.qspec.G.has_successor(anode_type, anode_type_string):
                    anode_maxlen = '%s -> maxLength' % anode
                    if not self.qspec.G.has_successor(anode, anode_maxlen):
                        score = 1
                        remed_clues.append(self.fix_template % anode)

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
