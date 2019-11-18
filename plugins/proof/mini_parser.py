#! /usr/bin/env python3
import sys
from argparse import FileType, ArgumentParser as Ap

import ply.lex as lex
import ply.yacc as yacc


class TypeTokenError(TypeError):
    pass


class YaccSyntaxError(SyntaxError):
    pass


class MyLexer:
    tokens = ['AND', 'OR', 'LPARENT', 'RPARENT', 'SEMICOLON', 'ASSUME', 'NONDET']

    t_ignore = ' \t'
    t_AND = r'\&\&'
    t_OR = r'\|\|'
    t_LPARENT = r'\('
    t_RPARENT = r'\)'
    t_SEMICOLON = ';'
    t_ASSUME = 'assume'
    t_NONDET = 'nondet'

    def t_error(self, t):
        raise TypeTokenError

    def __init__(self):
        self.lexer = lex.lex(module=self)


class MyParser:
    """Parser recognising a string of this kind :
    assume(((nondet()) && ((nondet()) || (nondet()) ) ) && ((nondet()) || (nondet())));

       top : ASSUME LPARENT expr RPARENT SEMICOLON
      expr : orexpr
    orexpr : andexpr
           | andexpr AND andexpr
   andexpr : simplexpr
           | simplexpr OR simplexpr
 simplexpr : NONDET LPARENT RPARENT
           | LPARENT expr RPARENT"""

    tokens = MyLexer.tokens

    def __init__(self):
        self.lexer = MyLexer()
        self.parser = yacc.yacc(module=self)

    def parse(self, input_str):
        return self.parser.parse(input_str, )

    def p_error(self, p):
        raise YaccSyntaxError("%s is not recognized as a valid syntax\n"
                              "      top ::= assume(expr);\n\n"
                              "     expr ::= orexpr\n\n"
                              "   orexpr ::= andexpr\n"
                              "            | andexpr || andexpr\n\n"
                              "  andexpr ::= simplexpr\n"
                              "            | simplexpr && simplexpr\n\n"
                              "simplexpr ::= nondet()\n"
                              "            | ( expr )" % p)

    def p_top(self, p):
        """top : ASSUME LPARENT expr RPARENT SEMICOLON"""
        p[0] = "assume(nondet());"

    # Other functions "return" None since we
    # just want to rewrite the recognized line
    # as "assume(nondet());"
    def p_expr_simple(self, p):
        """expr : orexpr"""
        # p[0] = p[1]
        p[0] = None

    def p_orexpr_simple(self, p):
        """orexpr : andexpr"""
        p[0] = None

    def p_orexpr_and(self, p):
        """orexpr : andexpr OR andexpr"""
        p[0] = None

    def p_andexpr_simple(self, p):
        """andexpr : simplexpr"""
        p[0] = None

    def p_andexpr_OR(self, p):
        """andexpr : simplexpr AND simplexpr"""
        p[0] = None

    def p_simplexpr(self, p):
        """simplexpr : NONDET LPARENT RPARENT"""
        p[0] = None

    def p_simplexpr_parent(self, p):
        """simplexpr : LPARENT expr RPARENT"""
        p[0] = None


def rewrite_file(file_path, output):
    with file_path as fin, output as fout:
        for line in fin:
            if line and not line.isspace():
                try:
                    res = MyParser().parse(line.strip())
                    fout.write("%s\n" % res)
                except TypeTokenError:
                    fout.write(line)
                except YaccSyntaxError:
                    fout.write(line)
            else:
                fout.write("\n")


if __name__ == '__main__':
    parser = Ap()
    parser.add_argument('-i', '--input', help='Input file', type=FileType('r'), default=sys.stdin)
    parser.add_argument('-o', '--output', help='Output file', type=FileType('w'), default=sys.stdout)
    args = parser.parse_args()

    rewrite_file(args.input, args.output)