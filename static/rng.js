// JavaScript function to generate 6 random unique values in order and populate form
function luckyDip() {

    // create empty set
    let draw = new Set();

    // while set does not contain 6 values, create a random value between 1 and 60
    while (draw.size < 6) {
        let randomBuffer = new Uint32Array(1); // creation of a typed array of 32-bit unsigned integers
        window.crypto.getRandomValues(randomBuffer); // randomBuffer array is full of cryptographically strong random values
        let randomNumber = randomBuffer[0] / (0xFFFFFFFF); // this divides the value held in randomBuffer by the 32-bit unsigned integer maximum value
        let min = Math.ceil(1); // rounds up a number to 1
        let max = Math.floor(60); //  returns the largest integer less than or equal to 60
        let value = Math.floor(randomNumber * (max - min + 1) + min); // converts randomNumber to an integer between 1 and 60

        // sets cannot contain duplicates so value is only added if it does not exist in set
        draw.add(value)
    }

    // turn set into an array
    let a = Array.from(draw);

    // sort array into size order
    a.sort(function (a, b) {
        return a - b;
    });

    // add values to fields in create draw form
    for (let i = 0; i < 6; i++) {
        document.getElementById("no" + (i + 1)).value = a[i];
    }
}