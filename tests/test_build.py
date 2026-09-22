import tempfile
import unittest
from pathlib import Path
from build import parse, covered, guard, build

class Tests(unittest.TestCase):
    def test_cosmetic(self):
        for mark in ('##','#@#','#?#','#$#','#$?#','#%#','#@?#'):
            with self.subTest(mark=mark):
                b,_,_=parse('||ads.example.com^\nexample.org'+mark+'div.ad','abp')
                self.assertEqual(b,{'ads.example.com'})
    def test_no_abp_bare_domain(self):
        b,_,_=parse('||ads.example.com^\nexample.org','abp')
        self.assertEqual(b,{'ads.example.com'})
    def test_conditional_blocks(self):
        b,_,_=parse('||ads.example.com^\n||cdn.example.com^$script','abp')
        self.assertEqual(b,{'ads.example.com'})
    def test_badfilter(self):
        b,_,_=parse('||keep.example.com^\n||ads.example.com^\n||ads.example.com^$badfilter','abp')
        self.assertEqual(b,{'keep.example.com'})
    def test_priority_policy(self):
        b,a,_=parse('||ads.example.com^$important\n@@||ads.example.com^','abp')
        self.assertFalse({d for d in b if not covered(d,a)})
    def test_parent_exception(self):
        self.assertTrue(covered('ads.example.com',{'example.com'}))
        self.assertFalse(covered('notexample.com',{'example.com'}))
    def test_conditional_exception(self):
        _,a,_=parse('||cdn.example.com^\n@@||cdn.example.com/path$domain=shop.org','abp')
        self.assertEqual(a,{'cdn.example.com'})
    def test_hosts(self):
        b,_,_=parse('0.0.0.0 example.com sub.example.com\n192.0.2.1 safe.example.com\n127.0.0.1 localhost','hosts')
        self.assertEqual(b,{'example.com','sub.example.com'})
    def test_preprocessor(self):
        b,_,_=parse('||keep.example.com^\n!#if env\n||skip.example.com^\n!#endif','abp')
        self.assertEqual(b,{'keep.example.com'})
    def test_empty_html(self):
        for s in ('','<html>error</html>','! comments only'):
            with self.assertRaises(ValueError): parse(s,'abp')
    def test_guard(self):
        for n in (0,74,151):
            with self.assertRaises(ValueError): guard(n,100,'test',False)
        guard(100,100,'test',False)
        guard(50,100,'test',True)
    def test_no_write_on_failure(self):
        for response in ('','<html>error</html>'):
            with tempfile.TemporaryDirectory() as temp:
                p=Path(temp)
                (p/'sources.txt').write_text('abp 1 https://example.org/list')
                (p/'rules').mkdir()
                old=p/'rules/adblockhosts.txt'
                old.write_text('previous good version')
                with self.assertRaises(ValueError): build(p,lambda u:response)
                self.assertEqual(old.read_text(),'previous good version')
    def test_local_priority_and_determinism(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'sources.txt').write_text('abp 1 https://example.org/list')
            (p/'blocklist.txt').write_text('ads.example.com\nkeep.example.org')
            (p/'allowlist.txt').write_text('*.example.com')
            fetch=lambda u:'||ads.example.com^\n@@||example.com^'
            build(p,fetch)
            first=(p/'rules/adblockhosts.txt').read_bytes()
            self.assertIn(b'keep.example.org',first)
            self.assertNotIn(b'ads.example.com',first)
            build(p,fetch)
            self.assertEqual(first,(p/'rules/adblockhosts.txt').read_bytes())
    def test_disabled_exception(self):
        b,a,_=parse('||ads.example.com^\n@@||ads.example.com^\n@@||ads.example.com^$badfilter','abp')
        self.assertEqual(b,{'ads.example.com'})
        self.assertFalse(a)
    def test_every_line_accounted_for(self):
        text='! comment\n\n[Adblock Plus 2.0]\n||ads.example.com^\nweird/file\nexample.com#%#script'
        _,_,stats=parse(text,'abp')
        self.assertEqual(stats['lines'],sum(v for k,v in stats.items() if k != 'lines'))
    def test_invalid_preprocessor(self):
        with self.assertRaises(ValueError):
            parse('||ads.example.com^\n!#if missing_end','abp')
    def test_minimum_network_and_partial_failure_preserve_outputs(self):
        for mode in ('network','partial','minimum'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                p=Path(temp)
                (p/'sources.txt').write_text('abp 1 https://a/list\nhosts 2 https://b/list')
                (p/'rules').mkdir()
                output=p/'rules/adblockhosts.txt'
                output.write_text('good')
                stats=p/'rules/stats.json'
                stats.write_text('{}')
                def fetch(url):
                    if mode == 'network' or (mode == 'partial' and url == 'https://b/list'):
                        raise OSError('simulated network failure')
                    return '||ads.example.com^' if url == 'https://a/list' else '0.0.0.0 ads.example.org'
                with self.assertRaises((ValueError,OSError)):
                    build(p,fetch)
                self.assertEqual(output.read_text(),'good')
                self.assertEqual(stats.read_text(),'{}')
    def test_domains_and_unknown_format(self):
        b,_,_=parse('example.com\nsub.example.com','domains')
        self.assertEqual(b,{'example.com','sub.example.com'})
        with self.assertRaises(ValueError): parse('example.com','auto')
    def test_large_change_preserves_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'sources.txt').write_text('abp 1 https://a/list')
            fetch=lambda u:'\n'.join('||a'+str(i)+'.example.com^' for i in range(10))
            build(p,fetch)
            old=(p/'rules/adblockhosts.txt').read_bytes()
            with self.assertRaises(ValueError): build(p,lambda u:'||a0.example.com^')
            self.assertEqual(old,(p/'rules/adblockhosts.txt').read_bytes())

if __name__ == '__main__': unittest.main()
