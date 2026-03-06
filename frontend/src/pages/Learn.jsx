const learnSections = [
  {
    title: 'What is Ransomware?',
    icon: 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    content: 'Ransomware is malicious software that encrypts your files and demands payment for their release. Attackers often deliver ransomware through deceptive links and websites that appear legitimate.',
    color: 'red'
  },
  {
    title: 'How Ransomware URLs Work',
    icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
    content: 'Ransomware URLs are links that lead to malicious websites designed to infect your device. These sites may download malware automatically, trick you into downloading infected files, or steal your credentials.',
    color: 'orange'
  },
  {
    title: 'Red Flags to Watch For',
    icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
    items: [
      'URLs with misspelled domain names (typosquatting)',
      'Unusual top-level domains (.xyz, .top, .click)',
      'Excessive hyphens or numbers in domains',
      'HTTP instead of HTTPS',
      'URLs that don\'t match the supposed sender',
      'Unexpected urgent messages demanding action',
      'Links in unsolicited emails or messages'
    ],
    color: 'red'
  },
  {
    title: 'Common Attack Patterns',
    icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    items: [
      'Fake software updates (especially Adobe, Java, browsers)',
      'Phishing emails impersonating banks, shipping companies, or tech support',
      'Pirated software or media download sites',
      'Fake antivirus alerts',
      'Cryptocurrency giveaway scams',
      'Fake job or investment opportunities'
    ],
    color: 'amber'
  },
  {
    title: 'How to Protect Yourself',
    icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    items: [
      'Always verify the URL before clicking',
      'Use our URL Scanner to check suspicious links',
      'Keep your software and browsers updated',
      'Use strong, unique passwords',
      'Enable two-factor authentication',
      'Never download attachments from unknown sources',
      'Use reputable antivirus software'
    ],
    color: 'green'
  },
  {
    title: 'What to Do If Infected',
    icon: 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    items: [
      'Disconnect from the internet immediately',
      'Don\'t pay the ransom - there\'s no guarantee you\'ll get your files back',
      'Take photos of the ransom note',
      'Report to local authorities and cybersecurity agencies',
      'Try restoring from backups if available',
      'Consider professional data recovery services',
      'Scan your system with updated antivirus software'
    ],
    color: 'red'
  }
];

const examples = [
  {
    url: 'https://www.paypa1.com/login',
    isFake: true,
    explanation: 'Uses number "1" instead of letter "l" - classic typosquatting'
  },
  {
    url: 'https://microsoft-support-verify.xyz/update',
    isFake: true,
    explanation: 'Suspicious .xyz domain with urgent language'
  },
  {
    url: 'https://www.amazon.com/orders/123456',
    isFake: false,
    explanation: 'Legitimate Amazon domain with normal-looking path'
  },
  {
    url: 'https://secure-bank.com.login-verify.net',
    isFake: true,
    explanation: 'Attempting to look like a bank by adding extra subdomains'
  }
];

export default function Learn() {
  const colorClasses = {
    red: { bg: 'bg-red-50', border: 'border-red-200', icon: 'bg-red-100 text-red-600' },
    orange: { bg: 'bg-orange-50', border: 'border-orange-200', icon: 'bg-orange-100 text-orange-600' },
    amber: { bg: 'bg-amber-50', border: 'border-amber-200', icon: 'bg-amber-100 text-amber-600' },
    green: { bg: 'bg-green-50', border: 'border-green-200', icon: 'bg-green-100 text-green-600' }
  };

  return (
    <div className="space-y-8 animate-slide-up">
      <div>
        <h2 className="text-2xl font-bold text-slate-800">Learn About Ransomware URLs</h2>
        <p className="text-slate-500 mt-1">Understand the threats and how to protect yourself</p>
      </div>

      <div className="grid gap-6">
        {learnSections.map((section, idx) => {
          const colors = colorClasses[section.color];
          return (
            <div key={idx} className={`bg-white border ${colors.border} rounded-xl p-6 shadow-sm`}>
              <div className="flex items-start gap-4">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${colors.icon}`}>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={section.icon} />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-slate-800">{section.title}</h3>
                  {section.content && (
                    <p className="text-slate-600 mt-2">{section.content}</p>
                  )}
                  {section.items && (
                    <ul className="mt-3 space-y-2">
                      {section.items.map((item, i) => (
                        <li key={i} className="flex items-start gap-2 text-slate-600">
                          <svg className="w-5 h-5 text-slate-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          {item}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-slate-800 mb-4">URL Examples</h3>
        <p className="text-slate-600 mb-4">Learn to identify malicious URLs with these examples:</p>
        <div className="space-y-3">
          {examples.map((ex, idx) => (
            <div key={idx} className={`p-4 rounded-lg ${ex.isFake ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'}`}>
              <div className="flex items-center justify-between mb-2">
                <code className={`font-mono text-sm ${ex.isFake ? 'text-red-700' : 'text-green-700'}`}>{ex.url}</code>
                <span className={`px-2 py-1 rounded text-xs font-medium ${ex.isFake ? 'bg-red-200 text-red-700' : 'bg-green-200 text-green-700'}`}>
                  {ex.isFake ? 'Malicious' : 'Legitimate'}
                </span>
              </div>
              <p className="text-sm text-slate-600">{ex.explanation}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-xl p-6 text-white">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-white/20 flex items-center justify-center">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-semibold">Not sure about a URL?</h3>
            <p className="text-blue-100 mt-1">Use our URL Scanner to analyze any suspicious link before visiting it.</p>
          </div>
          <a href="/ransomeware/scanner" className="ml-auto px-4 py-2 bg-white text-blue-600 font-medium rounded-lg hover:bg-blue-50 transition-colors">
            Scan Now
          </a>
        </div>
      </div>
    </div>
  );
}
