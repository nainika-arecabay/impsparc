from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecSecurityAttr02(ScoreNode):

    def __init__(self, qspec, target_obj=None, attr_wt=7):
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
            '[CVSPS002] [%s]: Credentials should not be transported in '\
            'cleartext. Use only https scheme.'

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
        return 'sps-sec-attr02'

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

        schemes_node = '%s -> schemes' % self.qspec.ROOT_NODE
        has_https = False
        for scheme_prefix in self.qspec.G.neighbors(schemes_node):
            https_node = '%s -> https' % scheme_prefix
            if self.qspec.G.has_node(https_node):
                has_https = True

        num_schemes = len(list(self.qspec.G.neighbors(schemes_node)))

        if ((not has_https) or (has_https and num_schemes > 1)):
            score = 1
            remed_clues.append(self.fix_template % schemes_node)

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
