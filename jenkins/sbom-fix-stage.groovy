// Stage to paste into a service Jenkinsfile, right after the SBOM is generated (SBOMFIX-804).
// Exit codes: 0 unchanged, 1 fixed, 2 cannot fix, 3 forbidden data loss, 4 quality gate, 5 verification failed,
// 7 no component has a purl type Checkmarx supports (Checkmarx would fail the scan).
// The upload below uses the cx CLI, which reads CycloneDX up to 1.6, so the profile is checkmarx-cli.
stage('SBOM: fix for Checkmarx') {
  steps {
    sh '''
      set +e
      docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 \
        fix build/sbom.json --profile checkmarx-cli --profile compliance --out build/sbom-fixed
      rc=$?
      set -e
      if [ "$rc" -ge 2 ]; then
        echo "sbom-fixer exit code $rc - see build/sbom-fixed/*.notes.txt"
        exit "$rc"
      fi
    '''
  }
  post {
    always { archiveArtifacts artifacts: 'build/sbom.json, build/sbom-fixed/**', allowEmptyArchive: true }
  }
}

stage('Checkmarx SCA') {
  steps {
    // Use the flags your cx version documents for SBOM import (cx scan create --help).
    withCredentials([string(credentialsId: 'cx-client-secret', variable: 'CX_CLIENT_SECRET')]) {
      sh 'cx scan create --project-name "${JOB_NAME}" --branch "${BRANCH_NAME}" -s build/sbom-fixed/sbom.checkmarx-cli.cdx.json --scan-types sca --sbom-only'
    }
  }
}
