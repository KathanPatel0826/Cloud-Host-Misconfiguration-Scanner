pipeline {
  agent any

  parameters {
    string(name: 'MAX_TOTAL_SCORE', defaultValue: '80', description: 'Fail if total risk score exceeds this')
    string(name: 'MIN_PASS_GRADE', defaultValue: 'C', description: 'Fail if grade is below this (D/F)')
  }

  environment {
    NORMALIZED_JSON = 'out/normalized_findings.json'
    OUT_DIR         = 'out'
    REPORT_HTML     = 'out/risk_report.html'
    REPORT_PDF      = 'out/risk_report.pdf'
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
          pip install jinja2 weasyprint || true
        '''
      }
    }

    // your existing normalization stage goes before this and writes out/normalized_findings.json

    stage('Risk Report') {
      steps {
        sh '''
          . .venv/bin/activate
          python3 score_and_report.py --in "$NORMALIZED_JSON" --out "$OUT_DIR" --pdf || \
          python3 score_and_report.py --in "$NORMALIZED_JSON" --out "$OUT_DIR"
        '''
      }
    }

    stage('Publish Report') {
      steps {
        archiveArtifacts artifacts: 'out/risk_report.*', fingerprint: true
        publishHTML(target: [
          reportDir: 'out',
          reportFiles: 'risk_report.html',
          reportName: 'Risk Report',
          keepAll: true,
          alwaysLinkToLastBuild: true
        ])
      }
    }

    stage('Quality Gate') {
      steps {
        script {
          // Parse total score + grade from the HTML (quick and dependency-free)
          def totalScore = sh(
            script: "grep -o 'Total Risk Score</div><div><b>[^<]*' ${env.REPORT_HTML} | sed 's/.*<b>//'",
            returnStdout: true
          ).trim()

          def grade = sh(
            script: "grep -o 'Risk Grade</div><div class=\"grade\">[^<]*' ${env.REPORT_HTML} | sed 's/.*grade\">//'",
            returnStdout: true
          ).trim()

          echo "Quality Gate => totalScore=${totalScore}, grade=${grade}"

          // Numeric gate
          if (totalScore?.isNumber() && totalScore.toFloat() > params.MAX_TOTAL_SCORE.toFloat()) {
            error "Quality Gate failed: total score ${totalScore} > ${params.MAX_TOTAL_SCORE}"
          }

          // Grade gate (rank A>B>C>D>F)
          def rank = ['A':5, 'B':4, 'C':3, 'D':2, 'F':1]
          if (rank.get(grade, 1) < rank.get(params.MIN_PASS_GRADE, 3)) {
            error "Quality Gate failed: grade ${grade} worse than ${params.MIN_PASS_GRADE}"
          }
        }
      }
    }
  }

  post {
    always { echo 'Pipeline finished (reports archived & published).' }
  }
}
