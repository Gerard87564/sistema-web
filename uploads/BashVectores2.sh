#!/bin/bash

countA=0
countP=0
count=0 

echo "Quin format vols generar de sortida?"
echo "1) CSV"
echo "2) JSON"
echo "3) HTML"
read option

while IFS= read -r line; do
    IFS=";" read -ra values <<< "$line"
    
    nomCog=${values[0]}
    edat=${values[1]}
    rol=${values[4]}

    if [[ $rol == *"Teacher"* ]]; then
        read -ra values2 <<< "${values[@]}"
        echo "${values2[@]}" >> Downloads/fileTeachers.txt

        ((countP++))
    elif [[ $rol == *"Student"* ]]; then
        read -ra values3 <<< "${values[@]}"
        echo "${values3[@]}" >> Downloads/fileAlumnes.txt

        ((countA++))
    fi

    if [[ $option == 1 ]]; then
        fOut="sortida.csv"

        if [[ $count -eq 0 ]]; then
            echo "NomCognoms,edat,usuari,correu,Rol" > "$fOut"
            ((count++))
        fi
        
        echo "$(IFS=,; echo "${values[*]}")" >> "$fOut"
    elif [[ $option == 2 ]]; then
        fOut="sortida.json"

        echo "[]" > "$fOut"

        while IFS= read -r line; do
            IFS=";" read -ra values <<< "$line"

            person=$(jq -n \
            --arg nom "${values[0]}" \
            --arg edat "${values[1]}" \
            --arg user "${values[2]}" \
            --arg correu "${values[3]}" \
            --arg rol "${values[4]}" \
            '{NomCognoms: $nom, Edat: $edat, Usuari: $user, Correu: $correu, Rol: $rol}')

            jq ". += [$person]" "$fOut" > temp.json && mv temp.json "$fOut"

        done < Downloads/file.txt

    else 
        fOut="sortida.html"

        if [[ $count -eq 0 ]]; then
            echo "<html><body><ul>" > "$fOut"
            ((count++))
        fi

        for value in "${values[@]}"; do
            echo "<li>$value</li>" >> "$fOut"
            ((count++))
        done
        echo "---------------" >> "$fOut"
    fi

done < Downloads/file.txt

if [[ $option == 3 ]]; then
    echo "</ul></body></html>" >> "$fOut"
fi

echo "Alumnes: $countA"
echo "Professors: $countP"