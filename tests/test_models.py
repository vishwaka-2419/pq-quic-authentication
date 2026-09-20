import unittest,itertools,sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from models import Prefix,minimum_credit,feasibility,merkle_root,merkle_path,verify_path
class Models(unittest.TestCase):
 def test_empty(self):self.assertEqual(minimum_credit([]),0)
 def test_validated(self):self.assertEqual(minimum_credit([Prefix(9000,1,True)]),0)
 def test_bound(self):self.assertEqual(minimum_credit([Prefix(12000,2400)]),1600)
 def test_prefix_exclusion(self):self.assertEqual(minimum_credit([Prefix(7200,2400),Prefix(12000,2400,True)]),0)
 def test_rounding(self):self.assertEqual(minimum_credit([Prefix(7,2)]),1)
 def test_negative(self):
  with self.assertRaises(ValueError):minimum_credit([Prefix(-1,2)])
 def test_exhaustive(self):
  for s1,c1,s2,c2 in itertools.product(range(0,19,3),range(5),range(0,19,3),range(5)):
   if s2<s1 or c2<c1:continue
   seq=[Prefix(s1,c1),Prefix(s2,c2)];p=minimum_credit(seq)
   self.assertTrue(all(e.server_sent<=3*(e.client_received+p) for e in seq))
   if p:self.assertFalse(all(e.server_sent<=3*(e.client_received+p-1) for e in seq))
 def test_feasible(self):self.assertEqual(feasibility(6000,1200,2400,12000),'feasible')
 def test_amplification(self):self.assertEqual(feasibility(8000,0,2400,12000),'amplification')
 def test_congestion(self):self.assertEqual(feasibility(12100,0,4800,12000),'congestion')
 def test_both(self):self.assertEqual(feasibility(14000,0,2400,12000),'both')
 def test_early_ack(self):self.assertEqual(feasibility(10678,2400,4800,12000),'congestion')
 def test_padding_not_sufficient(self):self.assertEqual(feasibility(12397,0,9600,12000),'congestion')
 def test_merkle(self):
  leaves=[str(i).encode() for i in range(1024)];root=merkle_root(leaves)
  for i in [0,1,317,1023]:self.assertTrue(verify_path(leaves[i],i,merkle_path(leaves,i),root))
 def test_merkle_tamper(self):
  leaves=[str(i).encode() for i in range(16)];self.assertFalse(verify_path(b'wrong',4,merkle_path(leaves,4),merkle_root(leaves)))
 def test_integrity(self):
  report=json.loads((Path(__file__).resolve().parents[1]/'analysis/audit.json').read_text());self.assertEqual(report['integrity_issues'],[])
if __name__=='__main__':unittest.main(verbosity=2)
