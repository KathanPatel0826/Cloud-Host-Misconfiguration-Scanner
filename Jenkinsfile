pipeline {
  agent any

  options {
    timestamps()
    ansiColor('xterm')
    buildDiscarder(logRotator(numToKeepStr: '15'))
    disableConcurrentBuilds()
  }

  environment {
    PYTHONUNBUFFERED = '1'
    OUT_DIR    = 'out'     // keep reports + jsons here to make archiving simple
    REPORT_DIR = 'out'     // run_pipeline.sh will honor this env var
    LOG_DIR    = 'logs'
  }

  stages {

    stage('Init (clear old params)') {
      steps {
        script {
          // safety: clear old parameters if you had any previously
          properties([parameters([])])
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
          # ensure the script writes into OUT_DIR/REPORT_DIR we expect
          OUT_DIR="${OUT_DIR}" REPORT_DIR="${REPORT_DIR}" LOG_DIR="${LOG_DIR}" ./run_pipeline.sh
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate
          # If risk_report.html wasn't produced by your report generator,
          # build it from normalized json (keeps Quality Gate working).
          if [ ! -f "${OUT_DIR}/risk_report.html" ]; then
            python3 score_and_report.py --in "${OUT_DIR}/normalized_findings.json" --out "${OUT_DIR}" --pdf || true
          fi
        '''
      }
    }

    stage('Publish Report') {
      steps {
        // Archive everything that's useful for grading / evidence
        archiveArtifacts artifacts: 'out/**, reports/**, output/**, logs/**, last_*.json, last_*.html', fingerprint: true

        // Publish the risk report (HTML) from OUT_DIR
        publishHTML(target: [
          allowMissing: true,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'out',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report'
        ])

        // If you also render a general report.html into REPORT_DIR (out),
        // publish it too (safe if missing)
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
          // Parse score & grade out of the risk report if it exists
          def totalScore = sh(
            script: "grep -o 'Total Risk Score</div><div><b>[^<]*' ${OUT_DIR}/risk_report.html | sed 's/.*<b>//'",
            returnStdout: true
          ).trim()

          def grade = sh(
            script: "grep -o 'Risk Grade</div><div class=\"grade\">[^<]*' ${OUT_DIR}/risk_report.html | sed 's/.*grade\">//'",
            returnStdout: true
          ).trim()

          echo "Quality Gate => totalScore=${totalScore}, grade=${grade}"

          // Example pass condition (tune as you like):
          // - allow all (demo), or enforce thresholds
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
      // Uncomment if you want to keep workspace clean
      // cleanWs()
    }
  }
}
