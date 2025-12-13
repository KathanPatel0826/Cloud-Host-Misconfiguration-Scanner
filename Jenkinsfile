pipeline {
  agent any

  environment {
    REPORTS_DIR     = 'reports'
    INPUT_JSON      = 'reports/combined_summary.json'
    SUMMARY_JSON    = 'reports/risk_summary.json'

    DASHBOARD_URL   = 'http://192.168.31.128:8088/ingest'
    API_TOKEN       = 'MYTOKEN'

    ENFORCE_GATE    = 'false' // keep false to avoid blocking your demo
  }

  stages {

    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Setup Python deps') {
      steps {
        sh '''
          python3 -m venv .venv || true
          . .venv/bin/activate
          pip install --upgrade pip
          pip install jinja2 weasyprint requests pyyaml || true
        '''
      }
    }

    stage('Run Scanner (non-fatal)') {
      steps {
        sh '''
          . .venv/bin/activate

          # Run the project scanner. Allow AWS scan failures (Prowler exit) but continue.
          python3 main.py || true

          echo "[+] reports directory:"
          ls -lah reports || true
        '''
      }
    }

    stage('Precheck Input') {
      steps {
        sh '''
          if [ ! -f "${INPUT_JSON}" ]; then
            echo "ERROR: Missing ${INPUT_JSON}"
            echo "reports directory:"
            ls -lah reports || true
            exit 2
          fi
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate

          # Generate HTML+PDF from combined_summary.json
          python3 score_and_report.py --in "${INPUT_JSON}" --out "${REPORTS_DIR}" --pdf || \
          python3 score_and_report.py --in "${INPUT_JSON}" --out "${REPORTS_DIR}"

          echo "[+] Generated outputs:"
          ls -lah reports/risk_report.* reports/risk_summary.json || true
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'reports/risk_report.*', fingerprint: true

        publishHTML(target: [
          reportDir: 'reports',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report',
          keepAll: true,
          alwaysLinkToLastBuild: true,
          allowMissing: true
        ])
      }
    }

    stage('Push to Dashboard') {
      when { expression { return fileExists(env.SUMMARY_JSON) } }
      steps {
        sh '''
          echo "[+] Posting summary to dashboard: ${DASHBOARD_URL}"
          curl -sS -X POST "${DASHBOARD_URL}" \
            -H "Content-Type: application/json" \
            -H "X-API-KEY: ${API_TOKEN}" \
            --data @reports/risk_summary.json \
            || echo "Dashboard push failed (non-fatal)"
        '''
      }
    }
  }
   stage('Test Dashboard Connectivity') {
  steps {
    sh '''
      curl -v http://192.168.31.128:8088/health || true
    '''
  }
}


  post {
    always { echo "Pipeline completed." }
  }
}
