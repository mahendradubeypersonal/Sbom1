// Nightly job (SBOMFIX-703): fix every corpus file and import it into the Checkmarx verification project.
// Catches Checkmarx-side changes (a version that used to import and no longer does).
pipeline {
  agent any
  triggers { cron('H 2 * * *') }
  environment {
    CX_BASE_URI = credentials('cx-base-uri')
    CX_TENANT = credentials('cx-tenant')
    CX_CLIENT_ID = credentials('cx-client-id')
    CX_CLIENT_SECRET = credentials('cx-client-secret')
    SBOM_FIXER_CX_PROJECT = 'sbom-fixer-verification'
  }
  stages {
    stage('Corpus import') {
      steps {
        sh '''
          python3 -m venv .venv && .venv/bin/pip install -q -e .
          .venv/bin/python tools/run_corpus_checkmarx.py
        '''
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'corpus-import-report.json', allowEmptyArchive: true }
    failure { echo 'A corpus file no longer imports into Checkmarx. Check corpus-import-report.json and re-run the Step 02 matrix.' }
  }
}
