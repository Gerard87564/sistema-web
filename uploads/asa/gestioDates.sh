#!/bin/bash

menu() {
    echo "De quin directori vols generar un informe? "
}

generarHTML() {
    array=("${!1}")
    last_mod_setdies=$2
    
    echo "---------------" >> "informeS.html"
    
    for value in "${array[@]}"; do
        echo "<li>${value}</li>" >> "informeS.html"
    done

    echo "---------------" >> "informeS.html"

    echo "Data d'execució: $(date +"%Y-%m-%d %H:%M:%S")" >> "informeS.html"
    echo "Fa 7 dies: $(date -d @$last_mod_setdies +"%Y-%m-%d %H:%M:%S")" >> "informeS.html"
}

programa() {
    menu
    read directori

    echo "<html><body><ul>" >> "informeS.html"
    for file in $(find "$directori" -type f); do
        if [ -f "$file" ]; then
            size="La grandària és $(stat -c %s "$file")"
            name="$(awk -F"/" '{print $NF}' <<< "$file")"
            creation_date="Data creació $(stat -c %w "$file")"
            modification_date="Data modificació $(stat -c %y "$file")"
            last_mod=$(stat -c %Y "$file")
            current_date=$(date +%s)
            last_mod_setdies=$((current_date - 7 * 86400))

            if [ "$last_mod" -gt "$last_mod_setdies" ]; then
                modified_last_7_days="S'ha modificat en els últims 7 dies"
            else
                modified_last_7_days="No s'ha modificat en els últims 7 dies"
            fi

            array=("$name" "$size" "$creation_date" "$modification_date" "$modified_last_7_days")
            generarHTML array[@] "$last_mod_setdies"
        fi
    done
    echo "</ul></body></html>" >> ""informeS.html""
}

programa