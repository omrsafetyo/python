#!/bin/bash
package_name=("$@")
dynamic_folders=("python3.8" "python3.9" "python3.10" "python3.11")
mkdir -p "./$package_name/python/lib"

# requirements files
install_packages=0
FILE=~/environment/requirements.txt
if [ -f "$FILE" ]; then
  echo "$FILE exists."
  cp $FILE $package_name/.
  cd $package_name
  install_packages=1
fi

# any additional files to add to the layer
FILES=~/environment/additional_files.txt
echo "checking for $FILES"
if [ -f "$FILES" ]; then
  echo "$FILES exists."
  # Read each line in the file
  while read file_name; do
    # Check if the file exists
    echo "checking $file_name"
    if [ -f "$file_name" ]; then
      echo "Copying $file_name to ./python"
      cp "$file_name" "./python/."
    else
      echo "File $file_name does not exist."
    fi
  done < "$FILES"
else
  echo "no $FILES found"
fi


for dynamic_name in "${dynamic_folders[@]}"
do
  # Create the subfolder tree under the parent folder
  echo "STARTING $dynamic_name"
  sleep 3
  mkdir -p "python/lib/$dynamic_name/site-packages"
  if [[ install_packages -eq 1 ]]; then
    echo "Installing packages from requirements.txt for ${dynamic_name}"
    $dynamic_name -m pip install -r requirements.txt --target ./python/lib/$dynamic_name/site-packages
  else
    echo "requirements.txt not present"
  fi
  echo "FINISHED $dynamic_name"
done

zip ${package_name}.zip * -r
