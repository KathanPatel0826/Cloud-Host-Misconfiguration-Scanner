pipeline {
  agent any
  options { timestamps() }
  environment { VENV = "${WORKSPACE}/.venv" }
  stages {
    stage('Checkout'){ steps{ checkout scm } }
    stage('Python Setup'){
      steps{
        sh '''
          python3 -V
          test -d "$VENV" || python3 -m venv "$VENV"
          . "$VENV/bin/activate"
          pip install --upgrade pip
          [ -f requirements.txt ] && pip install -r requirements.txt || true
        '''
      }
    }
    stage('Verify Tools'){
      steps{
        sh '''
          prowler --version || echo "WARN: prowler not found"
          lynis --version || echo "WARN: lynis not found"
        '''
      }
    }
    stage('Run Security Pipeline'){
      steps{
        sh '''
          . "$VENV/bin/activate"
          chmod +x run_pipeline.sh
          ./run_pipeline.sh
        '''
      }
    }
    stage('Archive Artifacts'){
      steps{ archiveArtifacts artifacts: 'out/**, reports/**, logs/**', fingerprint: true }
    }
    stage('Publish HTML'){
      when{ expression { return fileExists('reports') } }
      steps{
        publishHTML(target: [reportDir: 'reports', reportFiles: '**/report.html', reportName: 'Security Reports', keepAll: true, allowMissing: true])
      }
    }
  }
}
