#!groovy

def gitBranch
def gitCommit
def shortCommit

node {
    def nodeJsHome = tool 'NodeJS16'
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
    }
    stage('Publish') {
        sshagent (credentials: ['bb0927b6-318c-4e4a-a3d8-ac89152185df']) {
            sh "npm config list"
            sh "npm publish --loglevel silly"
        }
    }
}
