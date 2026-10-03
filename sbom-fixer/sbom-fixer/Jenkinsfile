// CI for the sbom-fixer repository itself (SBOMFIX-201): lint, types, tests, image.
pipeline {
  agent any
  options { timestamps(); timeout(time: 30, unit: 'MINUTES') }
  stages {
    stage('Set up') {
      steps {
        sh '''
          python3 -m venv .venv
          .venv/bin/pip install -q --upgrade pip
          .venv/bin/pip install -q -e ".[dev]"
        '''
      }
    }
    stage('Lint and types') {
      steps {
        sh '.venv/bin/ruff check sbom_fixer tests tools'
        sh '.venv/bin/mypy sbom_fixer'
      }
    }
    stage('Tests') {
      steps {
        sh '.venv/bin/pytest --cov=sbom_fixer --cov-report=xml --cov-fail-under=85 --junitxml=pytest.xml'
      }
      post { always { junit 'pytest.xml' } }
    }
    stage('Image') {
      when { buildingTag() }
      steps { sh 'docker build -t sbom-fixer:${TAG_NAME#v} .' }
    }
  }
}
