#!groovy

def gitBranch
def gitCommit
def shortCommit

node {
    def nodeJsHome = tool 'NodeJS6'
    env.PATH = "${nodeJsHome}/bin:/usr/local/bin:${env.PATH}"

    stage('Checkout') {
        checkout scm
        gitBranch = sh(returnStdout: true, script: 'git rev-parse --abbrev-ref HEAD').trim()
        gitCommit = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
        shortCommit = gitCommit.take(6)
    }
    stage('Dependencies') {
        sh "npm install"
    }
    stage('Lint') {
        sh "npm run lint"
        sh "npm run format"
    }
    stage('Publish') {
        sh "npm publish"
    }
}
