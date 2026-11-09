import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]

def load(name, filepath):
    spec = importlib.util.spec_from_file_location(name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

ctl = load('controller', ROOT / 'legacy/appsclub_vip_controller.py')
helper = load('worker_helper', ROOT / 'legacy/appsclub_vip_k8s.py')
cleanup = load('legacy_cleanup', ROOT / 'legacy/appsclub_vip_cleanup_legacy.py')

class ControllerTests(unittest.TestCase):
    def test_firewall_no_unrestricted_established(self):
        p = [{'team':'2','challenge':'13','identity':'356e098052efd16a',
              'vip':'10.78.2.13','source_ip':'10.79.2.1','pod_ip':'10.42.0.14',
              'peers':['10.77.0.10/32']}]
        rules=ctl.build_rules(p)
        self.assertEqual(len(rules),4)
        fwds=[args for table,chain,args in rules if chain=='ACVIP_FWD']
        self.assertEqual(len(fwds),2)
        self.assertTrue(all('-s' in r and '-d' in r for r in fwds))
        self.assertTrue(any('ESTABLISHED,RELATED' in r for r in fwds))
        self.assertTrue(any('10.77.0.10/32' in r and '10.42.0.14/32' in r for r in fwds))
        self.assertEqual(ctl.build_rules([]), [])

    def test_policy_wrapper_rejects_privilege_escalation(self):
        x={'team':'2','challenge':'13','identity':'356e098052efd16a',
           'vip':'10.78.2.13','source_ip':'10.79.2.1','pod_ip':'10.42.0.14',
           'peers':['10.77.0.10/32']}
        p=ctl.policy(x)
        self.assertEqual(helper.validate_policy(p),p)
        p['spec']['ingress'][0]['ports'].append({'protocol':'UDP'})
        with self.assertRaises(ValueError): helper.validate_policy(p)

    def test_legacy_cleaner_is_specific(self):
        rule = ['-A','FORWARD','-s','10.77.0.10/32','-d','10.60.2.10/32',
                '-i','wg0','-p','tcp','-m','tcp','--dport','32667','-j','ACCEPT']
        self.assertTrue(cleanup.is_fixed(rule, 'FORWARD', 'filter'))
        rule[rule.index('-d')+1] = '10.60.2.11/32'
        self.assertFalse(cleanup.is_fixed(rule, 'FORWARD', 'filter'))
        returns = ['-A','FORWARD','-i','eth0','-o','wg0','-m','conntrack',
                   '--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']
        self.assertTrue(cleanup.is_fixed(returns, 'FORWARD', 'filter'))

    def test_ownership_selects_one_ready_pod(self):
        ident='356e098052efd16a'
        svc={'kind':'Service','metadata':{'labels':{ctl.POD_LABEL:ident}},
             'spec':{'ports':[{'nodePort':30885}]}}
        pod={'kind':'Pod','metadata':{'labels':{ctl.POD_LABEL:ident}},
             'status':{'podIP':'10.42.0.14','phase':'Running',
                       'conditions':[{'type':'Ready','status':'True'}]}}
        np={'kind':'NetworkPolicy','metadata':{'name':'emp-ntp-test','labels':{ctl.POD_LABEL:ident}}}
        with patch.object(ctl,'get_instances',return_value=[{'challengeId':'13','sourceId':'2',
                                                            'connectionInfo':'http://10.60.2.10:30885'}]):
            result=ctl.desired({'2':['10.77.0.10/32']},[svc,pod,np])
        self.assertEqual(result[0]['vip'],'10.78.2.13')
        self.assertEqual(result[0]['pod_ip'],'10.42.0.14')

if __name__=='__main__': unittest.main()
