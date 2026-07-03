#!groovy

def gitBranch
def gitCommit
def shortCommit

def frontendDockerImage = "docker-registry-v2.smartling.net/smartling-build-fe:node-22"
def image = docker.image(frontendDockerImage)
image.pull()

def dockerOptions = "-v ${env.WORKSPACE}:/app -v node_22_modules_cache:/tmp/cache/node"


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
        image.inside(dockerOptions) {
            sh "npm install"
        }
    }
    stage('Lint') {
        image.inside(dockerOptions) {
            sh "npm run lint"
        }
    }
    if (gitBranch == "master") {
        stage('Publish') {
            sshagent (credentials: ['bb0927b6-318c-4e4a-a3d8-ac89152185df']) {
                sh "npm config list"
                sh "npm publish --loglevel silly"
            }
        }
    }
}
