/*!
* Start Bootstrap - Modern Business v5.0.7 (https://startbootstrap.com/template-overviews/modern-business)
* Copyright 2013-2023 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-modern-business/blob/master/LICENSE)
*/
// This file is intentionally blank
// Use this file to add JavaScript to your project

window.addEventListener('DOMContentLoaded', event => {

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
        if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
            document.body.classList.toggle('sb-sidenav-toggled');
        }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

});

// CHECKOUT PROCESS
// This function gets the value of a cookie by name
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// This function updates the cart count in the navbar
function updateCartCount(newCount) {
  const cartCountElement = document.getElementById('cart-count');
  if (newCount > 0) {
      cartCountElement.textContent = newCount;
  } else {
      cartCountElement.textContent = ''; // Hide the cart count when there are no items
  }
}

// This function updates the cart UI
function updateCartUI(cartCount, cartItems) {
  // Update the cart count
  updateCartCount(cartCount);
}

function updateCartSummary(subtotal, discount, total) {
  const subtotalElement = document.getElementById('subtotal');
  const discountElement = document.getElementById('discount');
  const totalElement = document.getElementById('total');

  if (subtotalElement && discountElement && totalElement) {
    fetch('/get_cart_details/', {
      method: 'POST',
      body: JSON.stringify({
        'subtotal': subtotal,
        'discount': discount,
        'total': total
    }),
      headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken')
      }
  })
      .then(response => response.json())
      .then(data => {
        // Set default values to "$0.00" if the retrieved values are null or undefined
        const formattedSubtotal = parseFloat(data.subtotal).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
        const formattedDiscount = parseFloat(data.discount).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
        const formattedTotal = parseFloat(data.total).toLocaleString('en-US', { style: 'currency', currency: 'USD' });

        // Update the UI with the formatted values
        subtotalElement.textContent = formattedSubtotal;
        discountElement.textContent = formattedDiscount;
        totalElement.textContent = formattedTotal;


        console.log("3 subtotal:", subtotalElement.textContent);
        console.log("2 discount:", discountElement.textContent);
        console.log("1 total:", totalElement.textContent);
      })
      .catch(error => {
        console.error('Error:', error);
      });
    } else {
        // Handle gracefully if any of the elements are not found
        console.error("One or more elements not found. Unable to update cart summary.");
        // Perform alternative action here, such as displaying an error message or updating the summary differently

    }
}
    
// This function adds an item to the cart
function addToCart(itemName, price, subscriptionPrice, quantity) {
  fetch('/add_to_cart/', {
      method: 'POST',
      body: JSON.stringify({
          'item_name': itemName,
          'price': price,
          'subscription_price': subscriptionPrice,
          'quantity': quantity
      }),
      headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken')
      }
  })
  .then(response => response.json())
  .then(data => {
      // Handle response data
      console.log(data);
      if (data.status === 'success') {
          // Update the cart count
          updateCartCount(data.cartCount);
          // Update the UI with the new cart details
          updateCartUI(data.cartCount, data.cart_items);

          // Store the cart summary values in session storage
          sessionStorage.setItem('subtotal', data.subtotal);
          sessionStorage.setItem('discount', data.discount);
          sessionStorage.setItem('total', data.total);

          updateCartSummary(data.subtotal, data.discount, data.total)
          console.log('ADD updateCartSummary:', data.subtotal, data.discount, data.total);
      }
  })
  .catch((error) => {
      console.error('Error:', error);
  });
}


// This function removes an item from the cart using AJAX
function removeFromCart(itemName, quantity) {
  fetch('/remove_from_cart/', {
      method: 'POST',
      body: JSON.stringify({
        'item_name': itemName, // Comes from the HTML
        'itemQuantity': quantity, // Updated quantity obtained from UI or passed as a parameter
        'subtotal': subtotal,
        'discount': discount,
        'total': total
    }),
      headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken')
      }
  })
  .then(response => response.json())
  .then(data => {
      // Handle response data
      console.log(data);
      if (data.status === 'success') {
        console.log("3The quantity is:", data.itemQuantity);
        // Update the cart count
        updateCartCount(data.cartCount);
        
        updateCartUI(data.cartCount, data.cart_items);

        updateCartSummary(data.subtotal, data.discount, data.total)
        console.log('REMOVE updateCartSummary:', data.subtotal, data.discount, data.total);

        // Check if the quantity is 0 and remove the item from UI if so
        if (data.itemQuantity === 0) {
          removeItemFromUI(itemName);
        } else {
          // Update the UI with the new cart details
          updateItemQuantityUI(itemName, data.itemQuantity)
          console.log("5PASSED IN updateItemQuantityUI:", itemName, data.itemQuantity);
        }
        // Check if cart is empty and display message if so
        const cartItemsDiv = document.getElementById('cartItems');
        if (data.cartCount === 0) {
            cartItemsDiv.innerHTML = '<p class="text-muted">There are no items in your cart.</p>';
        }
      } else {
          // Handle any errors
          console.error('Error removing item from cart:', data.error);
      }
  })
  .catch((error) => {
      console.error('Error:', error);
  });
}

function removeItemFromUI(itemName) {
  const itemToRemove = document.querySelector(`[data-item-id="${itemName}"]`).closest('.d-flex.align-items-center.mb-4');
  console.log("ITEM TO REMOVE:", itemToRemove);
  if (itemToRemove) {
    itemToRemove.remove();
  }
}

function updateItemQuantityUI(itemName, quantity) {
  const quantityElements = document.querySelectorAll('p.mb-0');
  console.log('quantityElements IS', quantityElements);

  let count = 0;
  let foundQuantityElement = false; // Flag to track if a Quantity element is found

  quantityElements.forEach((element, index) => {
    // Check if the element contains the itemName
    if (element.textContent.includes(itemName)) {
      count++; // INCREASE THE COUNT BASED ON EACH ITEM NAME
      // Get the index of the current element
      const elementNameIndex = index;
      console.log('Name Element index:', elementNameIndex);
      // Move to the next index
      const elementQuantityIndex = elementNameIndex + 3; // Move to the quantity element
      console.log('Quantity Element index:', elementQuantityIndex);
      // Check if the next element starts with 'Quantity:'
      if (quantityElements[elementQuantityIndex] && quantityElements[elementQuantityIndex].textContent.trim().startsWith('Quantity:')) {
        quantityElements[elementQuantityIndex].innerHTML = `Quantity: ${quantity}`;
        quantityElements[elementQuantityIndex].outerText = `Quantity: ${quantity}`;

        console.log(`Quantity updated for ${itemName}: ${quantity}`);
        console.log('quantityElements[elementQuantityIndex]', quantityElements[elementQuantityIndex]);

        foundQuantityElement = true; // Set the flag to true if a Quantity element is found
      }
    }
  });

  // Check if no Quantity element is found for the itemName
  if (!foundQuantityElement) {
    console.log(`No QUANTITY element found for ${itemName}. Refreshing the page and trying again.`);
    window.location.reload(); // Refresh the page if no element is found and try again
  }
}


 //PRICING Filter buttons
function filterSelection(c) {
  console.log('Filtering by category:', c);
  var x, i;
  x = document.querySelectorAll(".col-md-4");
  if (c === "all") {
    for (i = 0; i < x.length; i++) {
      x[i].style.display = "block";
    }
  } else {
    for (i = 0; i < x.length; i++) {
      if (x[i].getAttribute(c) !== null) {
        x[i].style.display = "block";
      } else {
        x[i].style.display = "none";
      }
    }
  }
}

