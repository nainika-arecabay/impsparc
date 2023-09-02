from cvsvc_apirisk.score.base import ScoreNode, check_remed
from cvsvc_apirisk.score.spec_security.sps_common import isvalid_url


class SpecSecSecurityAttr11(ScoreNode):

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
            '[CVSPS111] [%s]: Invalid or insecure "authorizationUrl".'

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
        return 'sps-sec-attr11'

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

        secdefn_node = '%s -> securityDefinitions' % self.qspec.ROOT_NODE
        if self.qspec.G.has_node(secdefn_node):
            for sec_schm_node in self.qspec.G.neighbors(secdefn_node):
                oauth2_node = '%s -> type -> oauth2' % sec_schm_node
                if self.qspec.G.has_node(oauth2_node):
                    authUrl_node = '%s -> authorizationUrl' % (sec_schm_node)
                    if self.qspec.G.has_node(authUrl_node):
                        url_node = list(self.qspec.G.neighbors(authUrl_node))[0]
                        url = self.qspec.G.nodes[url_node]['nodenameraw']
                        if ((not isvalid_url(url)) or
                                (not url.startswith('https://'))):
                            score = 1
                            remed_clues.append(self.fix_template % authUrl_node)

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
