let searchInput = document.querySelector("#search-input");

searchInput.addEventListener("keydown", function(event) {
    if(event.code === "Enter") {
        search();
    }
});

function search() {
    const input = searchInput.value;
    if (input != "" && input != null) {
        window.location.href = "https://www.google.com/search?q=" + encodeURIComponent(input);
    }
}

document.getElementById("google-search-btn").onclick = function () {
    search();
};

$('#id_button).click(function()
{
    $('body').css({'background-color': 'dark-gray'})
    $.post({% url,'change-background-color' %}, {color: 'dark-gray'}, function(){
          location.reload()  // to refresh the page with new background color
       })
})

