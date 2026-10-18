"""Self-test cho L1/L2. Chay: python3 -m unittest discover -s tests -v"""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dedup_repo as d

BASE = 'class A { // c\n int f(String s){ int n = 5; /* x */ if (s.length() > 10) { return n; } return Math.abs(7); } }'


def sig(src, name="f"):
    n = d.find_method(src, "A", name, "int f(String)")
    return (d.sha(" ".join(d.leaf_tokens(n, False))), d.sha(" ".join(d.leaf_tokens(n, True))),
            d.sha("\n".join(d.ast_tokens(n))), d.shingles(d.ast_tokens(n)))


class T(unittest.TestCase):
    def test_whitespace_comment_is_L1_strict(self):
        b = sig('class A {\n int f(String s){\n int n = 5;  if (s.length() > 10) { return n; }\n return Math.abs(7); } }')
        self.assertEqual(sig(BASE)[0], b[0])

    def test_numbers_is_L1_loose_not_strict(self):
        a, b = sig(BASE), sig('class A { int f(String s){ int n = 6; if (s.length() > 10) { return n; } return Math.abs(9); } }')
        self.assertNotEqual(a[0], b[0]); self.assertEqual(a[1], b[1])

    def test_rename_is_L2_not_L1(self):
        a, b = sig(BASE), sig('class A { int g(String t){ int k = 6; if (t.length() > 10) { return k; } return Math.abs(9); } }', "g")
        self.assertNotEqual(a[1], b[1]); self.assertEqual(a[2], b[2])

    def test_operator_change_is_not_L2(self):
        a, b = sig(BASE), sig('class A { int f(String s){ int n = 5; if (s.length() < 10) { return n; } return Math.abs(7); } }')
        self.assertNotEqual(a[2], b[2]); self.assertLess(d.jacc(a[3], b[3]), 0.9)


if __name__ == "__main__":
    unittest.main()
