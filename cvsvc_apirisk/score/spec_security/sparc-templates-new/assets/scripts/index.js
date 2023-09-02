const onDOMLoad = () => {
  // Update the customer name in the footer
  updateCustomerName("Pied Piper Inc.");

  // Update the creation date in the footer
  const timestamp = new Date().toLocaleString("en-us", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

  updateCreationDate(timestamp);

  updateReportNameInFooter("Imperva API Report");

  // Update bar chart for distribution by API method
  const methodsDistributionData = {
    labels: ["GET", "POST", "DELETE", "PUT", "PATCH"],
    data: [30000, 27000, 19000, 7000, 5000],
  };

  renderBarChart("distributionByMethod", "Methods", methodsDistributionData);

  // Update bar chart for distribution by param type
  const paramTypesDistributionData = {
    labels: ["String", "Boolean", "Integer", "Date", "Array"],
    data: [34000, 20000, 8500, 6500, 2000],
  };

  renderBarChart(
    "distributionByParamType",
    "Param Types",
    paramTypesDistributionData
  );

  // Update bar chart for distribution by param type
  const responseCodesDistributionData = {
    labels: ["200", "301", "302", "404", "402"],
    data: [34000, 20000, 8500, 6500, 2000],
  };

  renderBarChart(
    "distributionByResponseCode",
    "Response Codes",
    responseCodesDistributionData
  );

  // Update circular progress bar charts under
  // Frequently occuring violations
  renderCircularProgressBar("violationMetric1", 20);

  renderCircularProgressBar("violationMetric2", 50);
};

/**
 * Function to render bar chart for Input File Details
 */
const renderBarChart = (chartId, axisLabel, { labels, data }) => {
  const canvas = document.getElementById(chartId);
  canvas.width = canvas.parentNode.clientWidth;
  canvas.height = canvas.parentNode.clientHeight;

  const chart = new Chart(canvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: axisLabel,
          data: data,
          backgroundColor: ["#5081F2"],
          borderColor: ["#5081F2"],
          borderWidth: 1,
        },
      ],
    },
    options: {
      indexAxis: "y",
      scales: {
        y: {
          beginAtZero: true,
        },
      },
      plugins: {
        legend: false,
        // tooltip: {
        //   enabled: false,
        // },
      },
    },
  });
};

/**
 * Function to render circular progress bar for
 * Most Frequently Occuring Violations
 */
const renderCircularProgressBar = (chartId, value) => {
  const data = {
    labels: ["Test"],
    datasets: [
      {
        label: "My First Dataset",
        data: [value, 100 - value],
        backgroundColor: ["#285AE6", "#ACB9C5"],
        borderWidth: 0,
        hoverOffset: 4,
      },
    ],
  };

  const config = {
    type: "doughnut",
    data: data,
    options: {
      hover: { mode: null },
      cutout: "75%",
      plugins: {
        legend: false,
        tooltip: {
          enabled: false,
        },
      },
    },
  };

  const myChart = new Chart(document.getElementById(chartId), config);

  const percentageTextElement = document.querySelector(
    `#${chartId} + .violation-donut-percentage`
  );

  percentageTextElement.textContent = value + "%";
};

/**
 * Function to update report name in the footer section
 */
const updateReportNameInFooter = (reportName) => {
  const elementsList = document.querySelectorAll(".report-name");

  elementsList.forEach((element) => {
    element.textContent = reportName;
  });
};

/**
 * Function to update customer name in the footer section
 */
const updateCustomerName = (name) => {
  const elementsList = document.querySelectorAll(".customer");

  elementsList.forEach((element) => {
    element.textContent = `For: ${name}`;
  });
};

/**
 * Function to update the creation date in the footer section
 */
const updateCreationDate = (dateString) => {
  const elementsList = document.querySelectorAll(".date");

  elementsList.forEach((element) => {
    element.textContent = `Creation date: ${dateString}`;
  });
};
