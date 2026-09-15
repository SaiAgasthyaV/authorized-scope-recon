import unittest

from crawler import extract_javascript_urls


class CrawlerExtractionTests(unittest.TestCase):
    def test_js_extraction_resolves_relative_absolute_and_bundle_urls(self):
        html = """
        <script src="/static/runtime.78f4a1.js"></script>
        <script src="https://cdn.example.test/app.mjs"></script>
        <link rel="modulepreload" href="chunks/dashboard-a3c9.mjs">
        <a href="assets/legacy.js?build=17">legacy</a>
        """
        actual = extract_javascript_urls(html, "https://app.example.test/products/")
        self.assertEqual(actual, {
            "https://app.example.test/static/runtime.78f4a1.js",
            "https://cdn.example.test/app.mjs",
            "https://app.example.test/products/chunks/dashboard-a3c9.mjs",
            "https://app.example.test/products/assets/legacy.js?build=17",
        })

