pipeline {
  agent any

  options {
    timestamps()
    skipDefaultCheckout(true)
  }

  parameters {
    string(name: 'AWS_PROFILE', defaultValue: 'default', description: 'AWS CLI profile for Prowler (if applicable)')
    string(name: 'AWS_REGION',  defaultValue: 'us-east-2', description: 'AWS region for Prowler')
    string(name: 'DASHBOARD_API_KEY', defaultValue: 'MYTOKEN', description: 'API key expected by dashboard backend')
    string(name: 'DASHBOARD_URL', defaultValue: '', description: 'Optional override, e.g. http://host.docker.internal:8088/ingest')
  }

  environment {
    VENV_DIR = ".venv"
    REPORTS_DIR = "reports"
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
        sh 'git rev-parse --short HEAD'
      }
    }

    stage('Setup Python deps') {
      steps {
        sh '''
          set -e
          python3 -m venv "${VENV_DIR}"
          . "${VENV_DIR}/bin/activate"
          pip install --upgrade pip
          pip install jinja2 weasyprint requests pyyaml
        '''
      }
    }

    stage('Run Scanner (non-fatal)') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          sh '''
            set +e
            . "${VENV_DIR}/bin/activate"

            # Pass region/profile as environment variables if your code uses them (optional)
            export AWS_PROFILE="${AWS_PROFILE}"
            export AWS_REGION="${AWS_REGION}"

            python3 main.py
            rc=$?

            echo "[i] main.py exit code: $rc (non-fatal stage)"
            exit 0
          '''
        }
      }
    }

    stage('Build Findings') {
      steps {
        sh '''
          set -e
          . "${VENV_DIR}/bin/activate"

          mkdir -p "${REPORTS_DIR}"

          # This should read reports/aws_scan.json + reports/lynis findings and produce combined_findings.json
          python3 -m utils.build_findings

          echo "[+] reports directory:"
          ls -lah "${REPORTS_DIR}"

          test -f "${REPORTS_DIR}/combined_findings.json"
        '''
      }
    }

    stage('Risk Report') {
      steps {
        sh '''
          set -e
          . "${VENV_DIR}/bin/activate"

          # IMPORTANT: Use combined_findings.json (not combined_summary.json)
          python3 score_and_report.py \
            --in "${REPORTS_DIR}/combined_findings.json" \
            --out "${REPORTS_DIR}" \
            --pdf

          echo "[+] Generated outputs:"
          ls -lah "${REPORTS_DIR}/risk_report.html" "${REPORTS_DIR}/risk_report.pdf" "${REPORTS_DIR}/risk_summary.json"
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'reports/risk_report.html,reports/risk_report.pdf,reports/risk_summary.json,reports/combined_findings.json', fingerprint: true

        publishHTML(target: [
          allowMissing: false,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'reports',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report'
        ])
      }
    }

    stage('Push to Dashboard (non-fatal)') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          sh '''
            set +e
            FILE="reports/risk_summary.json"
            if [ ! -f "$FILE" ]; then
              echo "[!] Missing $FILE - skipping dashboard push"
              exit 0
            fi

            # Jenkins is likely running in a container. 127.0.0.1 refers to the Jenkins container itself.
            # We'll try:
            #  - user override (DASHBOARD_URL)
            #  - host.docker.internal (works on Docker Desktop; sometimes on Linux)
            #  - 172.17.0.1 (common Docker bridge gateway on Linux)
            if [ -n "${DASHBOARD_URL}" ]; then
              CANDIDATES="${DASHBOARD_URL}"
            else
              CANDIDATES="http://host.docker.internal:8088/ingest http://172.17.0.1:8088/ingest"
            fi

            echo "[+] Dashboard URL candidates: $CANDIDATES"

            pushed=0
            for url in $CANDIDATES; do
              echo "[+] Trying dashboard push to: $url"
              curl -sS --fail -X POST "$url" \
                -H "Content-Type: application/json" \
                -H "X-API-KEY: ${DASHBOARD_API_KEY}" \
                --data @"$FILE" && pushed=1 && break
              echo "[i] Push attempt failed for: $url"
            done

            if [ "$pushed" -eq 1 ]; then
              echo "[+] Dashboard push: SUCCESS"
            else
              echo "[!] Dashboard push failed for all candidates (non-fatal)"
            fi

            exit 0
          '''
        }
      }
    }
  }

  post {
    always {
      echo 'Pipeline completed.'
    }
  }
}
