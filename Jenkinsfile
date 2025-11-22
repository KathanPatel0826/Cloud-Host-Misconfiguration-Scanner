pipeline {
  agent any

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '15'))
    disableConcurrentBuilds()
  }

  environment {
    PYTHONUNBUFFERED = '1'
    OUT_DIR    = 'out'     // reports + JSONs
    REPORT_DIR = 'out'     // keep everything together
    LOG_DIR    = 'logs'
  }

  stages {

    stage('Init (clear old params)') {
      steps {
        script {
          properties([parameters([])])   // clear any stale params
          echo "Cleared leftover job parameters."
        }
      }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Setup Python deps') {
      steps {
        sh '''
          python3 -m venv .venv
          . .venv/bin/activate
          pip install --upgrade pip
          # deps used by generate_report.py / score_and_report.py
          pip install jinja2 weasyprint pyyaml
        '''
      }
    }

    stage('Security Scan + Normalize') {
      steps {
        sh '''
          . .venv/bin/activate
          chmod +x run_pipeline.sh
          OUT_DIR="${OUT_DIR}" REPORT_DIR="${REPORT_DIR}" LOG_DIR="${LOG_DIR}" ./run_pipeline.sh
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate
          # fallback: create risk report if not already produced by your report step
          if [ ! -f "${OUT_DIR}/risk_report.html" ]; then
            python3 score_and_report.py --in "${OUT_DIR}/normalized_findings.json" --out "${OUT_DIR}" --pdf || true
          fi
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'out/**, reports/**, output/**, logs/**, last_*.json, last_*.html', fingerprint: true

        publishHTML(target: [
          allowMissing: true,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'out',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report'
        ])

        publishHTML(target: [
          allowMissing: true,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'out',
          reportFiles: 'report.html',
          reportName: 'Security Reports'
        ])
      }
    }

    stage('Quality Gate') {
      steps {
        script {
          def totalScore = sh(
            script: "grep -o 'Total Risk Score</div><div><b>[^<]*' ${OUT_DIR}/risk_report.html | sed 's/.*<b>//'",
            returnStdout: true
          ).trim()

          def grade = sh(
            script: "grep -o 'Risk Grade</div><div class=\"grade\">[^<]*' ${OUT_DIR}/risk_report.html | sed 's/.*grade\">//'",
            returnStdout: true
          ).trim()

          echo "Quality Gate => totalScore=${totalScore}, grade=${grade}"

          // Adjust your pass/fail policy here if you want enforcement.
          currentBuild.result = 'SUCCESS'
        }
      }
    }
  }

  post {
    success {
      echo 'Pipeline finished (reports archived & published).'
    }
    failure {
      echo 'Pipeline failed.'
    }
    always {
      echo 'Build completed (post -> always).'
      // cleanWs()   // <- uncomment if you want to clean the workspace
    }
  }
}
