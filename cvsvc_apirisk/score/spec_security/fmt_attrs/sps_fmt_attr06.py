from cvsvc_apirisk.score.base import ScoreNode, check_remed


class SpecSecFormatAttr06(ScoreNode):

    def __init__(self, qspec, target_obj=None, attr_wt=2):
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

        self.fix_template = '[CVSPF006] [%s]: Contact info not provided or '\
                            'incorrect.'

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
        return 'sps-fmt-attr06'

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

        # info node is required
        contact_node = '%s -> info -> contact' % self.qspec.ROOT_NODE

        if not self.qspec.G.has_node(contact_node):
            score = 1
            remed_clues.append(self.fix_template % contact_node)
        else:
            email_node = '%s -> email' % contact_node
            # Check if email exists
            if not self.qspec.G.has_node(email_node):
                score = 1
                remed_clues.append(self.fix_template % email_node)
            else:
                # Check email string validity
                email_str = list(self.qspec.G.neighbors(email_node))[0]
                try:
                    un, dom = email_str.split('@')
                    if '.' not in dom:
                        raise
                except:
                    score = 1
                    remed_clues.append(self.fix_template % email_node)

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
