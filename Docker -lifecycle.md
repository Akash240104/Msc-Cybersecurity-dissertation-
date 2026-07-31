What are the actvities performed in order to get used to docker?

Practical Activities  : 

1)Verified Docker installation :- 
  Command :  docker --version 
  Output : docker version 29.1.3
  Therefore docker was successfully installed in my system.

2) Verified Docker Engine :
  Command : docker info
  The output obtained : 
  - Docker Engine is operational
  - Docker is using the overlayfs storage driver.
  - No containers were currently running.
  - One stopped container exists
  - One image had been downloaded.

  This is just to confirm docker is functioning correctly and ready for use.

3) First Docker Run : 
   Initially I started to test the docker by running hello world !
   Command : docker run hello-world
   Docker returned repository did not exist because docker searches for docker hub for the exact image name.
   Since docker searches docker hub for the exact image name , even a small spellling mistakes docker to fail because image names are case sensitive and must exist in the 
   registry.

4) Running the correct registry :
  command : docker run hello-world

  Docker automatically performed the following tasks.
  -  Checked whether the image existed.
  -  Connected to the docker hub
  -  Downloaded the  hello-world image
  -  Created a new container from the image
  -  started the container
  -  Displayed the output
  -  Stopped the container after execution
  This demonstrates the complete docker lifecycle

5)Viewing downloaded images : 
  command : docker images
  The hello-world image has been donwloaded and stored locally.
  This means Docker will not need to download the image again unless it is removed.

6)Viewing Containers : command : docker ps -a//
