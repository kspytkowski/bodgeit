#!/bin/bash

TOMCAT_PATH=/c/devTools/apache-tomcat-7.0.76

$TOMCAT_PATH/bin/shutdown.sh

ant deploy

$TOMCAT_PATH/bin/startup.sh
