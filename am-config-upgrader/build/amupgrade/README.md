# AM Config Upgrader - The AM Config Upgrade Tool

## About
AMupgrade is a tool for converting exported AM configuration files to be usable with a newer version of AM.

AMupgrade is intended for use alongside Amster and upgrading of File based configuration files.

AMupgrade does not perform inline upgrading of a running AM instance.  This is a tool for converting 
exported configuration from one version to be compatible to be imported into another.  This does not replace the 
current AM upgrade procedure at this time.

## Installation

### Prerequisites
The tool has the same Java requirements as Amster.

### Extracting
To install just extract the .zip file in a directory of your choosing - this will create an appropriately named folder.  You can run the tool from here or add the
extracted directory to your PATH environment variable to be able to run from anywhere.

## Using AM Config Upgrade

AMUpgrade supports upgrading the following versions of exported Amster configuration:
* to AM 5.5.0 from: 
  * AM 5.0 (14.0.0)
  * AM 5.1.* (14.1.*)
* to AM 6.0.0 from:
  * AM 5.5.* (14.5.*)
* to AM 6.5.0 from:
  * AM 6.0.*
* to AM 7.0.0 from:
  * AM 6.5.*
  
AMUpgrade also supports upgrading versions of file based configuration from 7.0.0 onwards:
* latest.groovy allows upgrading per-commit of AM.

### Prerequisites
You will need to have Amster exported config from a configured AM instance.  
Please see yor Amster documentation for your Amster version and how to export and import configuration.

### Running the command

To run this tool on Amster exported configuration run the command:
```
amupgrade -i <exported configuration> -o <output folder> -a <amster version> rules/<from>-to-<to>.groovy
```
To run this tool on file based configuration run the command:
```
amupgrade -i <exported configuration> -o <output folder> --fileBasedMode rules/latest.groovy
```

`<exported configuration>` = The folder containing the Amster-exported configuration that you wish to upgrade.  
Provided you give a different location for the output folder this configuration will not be changed.

`<output folder>` = The folder the new configuration will be saved to.  

`<amster version>` = This is the version of Amster that you intend to use for the new configuration.

`<from>` = The version pattern being upgraded from, e.g. `5.x.x`

`<to>` = The version pattern being upgraded to, e.g. `5.5.x`

#### Example
`amupgrade -i /input/myAM5Config/ -o /output/myAM5.5Config -a 14.0.0 rules/5.x.x-to-5.5.x.groovy`

#### Upgrading multiple version jumps

If the version span you are upgrading spans more than one major release (e.g. `5.0.0` to `6.0.0`), you may include 
multiple rules files to be run all together.  e.g.:

```
amupgrade -i /path/to/5.0.0/export -o /path/to/6.0.0/export -a 6.0.0 rules/5.x.x-to-5.5.x.groovy rules/5.5.x-to-6.x.x.groovy
```

Alternativly you may run the upgrader tool once for each major version in the span. e.g.:

```
amupgrade -i /path/to/5.0.0/export -o /path/to/5.5.0/export -a 5.5.0 rules/5.x.x-to-5.5.x.groovy
amupgrade -i /path/to/5.5.0/export -o /path/to/6.0.0/export -a 6.0.0 rules/5.5.x-to-6.x.x.groovy
```

### Logging and auditing
The ouput from amilio can be pipped to a file, or you may provided a logging file
output for extra logging.  AMUpgrade can run in verbose mode with the -v optional flag - this will allow a finer detail 
of logging.  
e.g.:
piped
```
amupgrade -i /path/to/6.5.0/export -o /path/to/7.0.0/export -a 6.0.0 -v rules/6.5.x-to-7.x.x.groovy | out.log
```
logged
```
amupgrade -i /path/to/6.5.0/export -o /path/to/7.0.0/export -a 6.0.0 -v --log-output out.log rules/6.5.x-to-7.x.x.groovy
```

for the highest level of logging use an external file with the verbose flag enabled