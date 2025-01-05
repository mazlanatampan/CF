<div>
  <!-- Sidebar -->
  <div
    id="sidebar"
    class="h-full fixed top-0 left-0 w-14 bg-white dark:bg-neutral-800 border-r-2 border-neutral-800 dark:border-white z-20 overflow-y-scroll scrollbar-hide transform transition-all duration-300"
    style="transform: translateX(-100%);"
  >
    <div class="text-2xl flex flex-col items-center h-full gap-4">
      <!-- Main Menu Item: Negara -->
      <button id="toggle-country-menu" class="text-white bg-neutral-800 p-2 rounded-md w-full text-center">
        Negara
      </button>

      <!-- Submenu Negara (hidden by default) -->
      <div id="country-menu" class="hidden flex flex-col items-center gap-2 mt-4 w-full">
        <!-- List of countries with flags, dynamically inserted here -->
        <div id="country-flag-list">
          <!-- Placeholder for dynamic flags -->
          PLACEHOLDER_BENDERA_NEGARA
        </div>
      </div>
    </div>
  </div>

  <!-- Sidebar Toggle Button (this will toggle the sidebar) -->
  <button 
    id="sidebar-toggle" 
    class="fixed left-0 top-1/2 z-30 transform -translate-x-1/2 bg-neutral-800 text-white p-3 rounded-full shadow-md"
  >
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-6 h-6">
      <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"></path>
    </svg>
  </button>
</div>

<script>
  // Function to toggle sidebar visibility
  const sidebar = document.getElementById('sidebar');
  const sidebarToggleButton = document.getElementById('sidebar-toggle');
  const toggleCountryMenuButton = document.getElementById('toggle-country-menu');
  const countryMenu = document.getElementById('country-menu');

  sidebarToggleButton.addEventListener('click', () => {
    const isSidebarVisible = sidebar.style.transform === 'translateX(0%)';
    
    if (isSidebarVisible) {
      // Close the sidebar
      sidebar.style.transform = 'translateX(-100%)';
    } else {
      // Open the sidebar
      sidebar.style.transform = 'translateX(0%)';
    }
  });

  // Toggle country menu visibility
  toggleCountryMenuButton.addEventListener('click', () => {
    countryMenu.classList.toggle('hidden'); // Show or hide the country submenu
  });
</script>
