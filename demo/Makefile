all: build

build:
	@(cd scripts; ./make_all.sh)

provision: provisioning/ProvisioningMain
	(cd scripts; ./deploy_provisioning.sh)

measure: #provisioning/ProvisioningMain
	(cd scripts; ./measure.sh)

provisioning/ProvisioningMain: build

clean:
	@(cd scripts; ./clean_all.sh)

run: appraisal/AppMain appraisal/goldenPcrComposite.txt
	@(cd appraisal; ./AppMain)

appraisal/AppMain : build

appraisal/goldenPcrComposite.txt : #provisioning/goldenPcrComposite.txt
#	(cd scripts; ./deploy_provisioning.sh)
