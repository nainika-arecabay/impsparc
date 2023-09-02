import json


#
# Custom scanner factory
#   context: the custom JSONDecoder object
#
def make_my_scanner(context):
    # reference to actual scanner (defined by the JSONDecoder)
    interal_scanner = json.scanner.py_make_scanner(context)

    #
    # customized _myscan
    #   string is the json string buf
    #   idx starts w 0 and advance as the parser scans
    #
    def _myscan(string, idx):
        try:
            nextchar = string[idx]
        except IndexError:  # ignore testing nextchar
            pass

        #
        # passing down custom parser
        #   before recursively parsing down, calculate the start line number
        #   when done, calculate the line number again to get the range
        #
        #   a dict object is added to the existing dict or appended to the array
        #   secret-handshake cvlrange26uel7Ao is entirely arbitrary to avoid conliction
        #
        if nextchar == '{':
            context.countlines(string, idx)
            startline = context.lineno
            (theobj, l) = context.parse_object((string, idx + 1),
                                               context.strict,
                                               _myscan,
                                               context.object_hook,
                                               context.object_pairs_hook)
            context.countlines(string, l)
            theobj['cvlrange26uel7Ao'] = (startline, context.lineno)
            return (theobj, l)
        elif nextchar == '[':
            context.countlines(string, idx)
            startline = context.lineno
            (theobj, l) = context.parse_array((string, idx + 1),
                                              _myscan)
            context.countlines(string, l)
            theobj.append({'cvlrange26uel7Ao': (startline, context.lineno)})
            return (theobj, l)
        else:
            context.countlines(string, idx)
            startline = context.lineno
            (theobj, l) = interal_scanner(string, idx)
            context.countlines(string, idx)
            newobj = (theobj, {'cvlrange26uel7Ao': (startline, context.lineno)})
            return (newobj, l)

    return _myscan


class SaveLineRangeDecoder(json.JSONDecoder):
    #
    # It is a one pass scanner, lineno starts with 1
    #  to make it efficient, everytime it is called, it
    #  counts lineno from last scanned indx
    #
    lastindx = 0
    lineno = 1

    def countlines(self, string, endindx):
        if endindx >= len(string):
            return
        while self.lastindx <= endindx:
            if string[self.lastindx] == '\n':
                self.lineno += 1
            self.lastindx += 1

    def __init__(self, object_hook=None, parse_float=None, parse_int=None,
                 parse_constant=None, strict=True, object_pairs_hook=None):

        json.JSONDecoder.__init__(self, object_hook=object_hook,
                                  parse_float=parse_float,
                                  parse_int=parse_int,
                                  parse_constant=parse_constant,
                                  strict=strict,
                                  object_pairs_hook=object_pairs_hook)

        self.lastindx = 0
        self.lineno = 1
        # override scanner, it was called scan_once in JSONDecoder
        self.scan_once = make_my_scanner(self)
