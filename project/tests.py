from django.test import TestCase
from django.urls import reverse
from .models import Repository, CryptoIssue

class CryptoIssueTests(TestCase):
    def setUp(self):
        self.repo = Repository.objects.create(
            name='test-repo',
            owner='test-owner',
            url='https://github.com/test-owner/test-repo'
        )
        self.issue = CryptoIssue.objects.create(
            repository=self.repo,
            title='Test Issue',
            body='Test body',
            issue_number=1,
            complexity='beginner'
        )

    def test_issue_list_view(self):
        response = self.client.get(reverse('crypto_issues:issue-list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Issue')