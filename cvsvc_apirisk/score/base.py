#!/usr/bin/python

import sys
from argparse import ArgumentParser
from configparser import ConfigParser


def check_meta(func):
    from functools import wraps
    @wraps(func)
    def wrapper(self):
        func(self)
        if self.score > 0:
            if self.meta is None:
                raise ValueError("meta should be assigned")
    return wrapper


class ScoreNode(object):

    def __init__(self):
        """
        Override at least the following methods:
        - __repr__()
        - compute()

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
        self.score = None
        self.meta = None
        self.children = {}      # If empty, means leaf node
        self.score = 0

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
        return 'UI friendly node description'

    def compute(self):
        """
        Compute the score. Two cases possible:
        1. If this node has children, then apply a function to compute the
        score using the scores from child nodes
        2. If this node is the leaf, compute the score as implemented.

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
        return

    def add_child(self, scnode):
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
        self.children[str(scnode)] = scnode
        return

    def list(self, recursive=False, layer=0):
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
        if recursive is False:
            for node in self.children:
                print('%s%s' % ('\t'*layer, node))
        else:
            # Do a DFS
            for node in self.children:
                node.list(recursive=recursive, layer=layer+1)

        return


def main(argv=sys.argv):
    apar = ArgumentParser()
    apar.add_argument('-c', dest='cfg_file')
    args = apar.parse_args()

    cpar = ConfigParser()
    cpar.read(args.cfg_file)

    return


if __name__ == '__main__':
    sys.exit(main())
