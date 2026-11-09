// Declarative pipeline: unit tests -> SAST scan (HTML + SARIF) -> archive reports.
// Works on Windows agents (bat) and Linux/macOS agents (sh). Needs Python 3.10+ on the agent.
pipeline {
  agent any
  options { timestamps() }
  stages {
    stage('Tests') {
      steps { script { run('python -m unittest discover -s tests -v') } }
    }
    stage('SAST scan') {
      steps {
        // samples/ and tests/ are intentionally vulnerable, so they are excluded from the gate.
        // A finding at HIGH or above marks the build UNSTABLE (use 'FAILURE' to block merges).
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
          script {
            run('python sast.py scan . --exclude samples,tests,reports --format html  --output reports/sast-report.html --exit-zero')
            run('python sast.py scan . --exclude samples,tests,reports --format sarif --output reports/sast.sarif --fail-on high')
          }
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/*.html, reports/*.sarif', allowEmptyArchive: true
      // Optional (needs the "Warnings Next Generation" plugin): show findings in the Jenkins UI
      // recordIssues tool: sarif(pattern: 'reports/*.sarif')
    }
  }
}

def run(cmd) {
  if (isUnix()) { sh cmd } else { bat cmd.replace('python', 'py') }
}
