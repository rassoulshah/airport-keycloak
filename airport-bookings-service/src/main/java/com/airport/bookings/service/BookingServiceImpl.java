/**
 * @author SIRAJ CHAUDHARY
 * 
 * https://github.com/SirajChaudhary
 * 
 * https://www.linkedin.com/in/sirajchaudhary/
 */

package com.airport.bookings.service;

import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.airport.bookings.email.BookingEmailService;
import com.airport.bookings.entity.BookingEntity;
import com.airport.bookings.feignclients.FlightFeignClient;
import com.airport.bookings.repository.BookingRepository;
import com.airport.bookings.request.Booking;
import com.airport.bookings.response.BookingResponse;
import com.airport.bookings.response.FlightResponse;
import com.airport.bookings.util.GeneratePNRNumber;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

//import javassist.NotFoundException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional(readOnly = true)
public class BookingServiceImpl implements BookingService {

	private static final ModelMapper modelMapper = new ModelMapper();

	@Autowired
	BookingRepository bookingRepository;

	@Autowired
	BookingEmailService bookingEmailService;

	@Autowired
	GeneratePNRNumber generatePNRNumber;

	@Autowired
	FlightFeignClient flightFeignClient;

	@Override
	@Transactional
	public BookingResponse createBooking(Booking booking) {
		log.info("starting bookingTicket() service method");

		/* map booking input object to booking entity object automatically */
		BookingEntity bookingEntity = modelMapper.map(booking, BookingEntity.class);

		/* generate and save a random PNR number */
		bookingEntity.setPnrNumber(generatePNRNumber.gePNRNumber());

		bookingEntity = bookingRepository.save(bookingEntity);

		BookingResponse bookingResponse = new BookingResponse(bookingEntity);

		/* calling the airport-flight-service using feign client */
		bookingResponse.setFlightResponse(flightFeignClient.getFlightById(bookingEntity.getFlightNumber()).getBody());

		/* email the booking information to the passenger */
		// bookingEmailService.sendEmail(bookingResponse.getEmail(), "Flight Booking
		// Confirmed", bookingResponse);

		return bookingResponse;
	}

	@Override
	public BookingResponse getBookingById(long id) {
		log.info("starting getBookingByBookingId() service method");

		BookingEntity bookingEntity = bookingRepository.findById(id)
				.orElseThrow(() -> new ResponseStatusException(
						HttpStatus.NOT_FOUND, "Booking with id " + id + " not found"));

		BookingResponse bookingResponse = new BookingResponse(bookingEntity);

		/* calling the airport-flight-service using feign client */
		bookingResponse.setFlightResponse(flightFeignClient.getFlightById(bookingEntity.getFlightNumber()).getBody());

		return bookingResponse;
	}

	@Override
	public BookingResponse findBookingByPNRNumber(String pnrNumber) {
		log.info("starting findBookingByPNRNumber() service method");
		BookingEntity bookingEntity = bookingRepository.findByPNRNumber(pnrNumber);
		BookingResponse bookingResponse = new BookingResponse(bookingEntity);

		/* calling the airport-flight-service using feign client */
		bookingResponse.setFlightResponse(flightFeignClient.getFlightById(bookingEntity.getFlightNumber()).getBody());

		return bookingResponse;
	}

	@Override
	public List<BookingResponse> getAllBookings() {
		log.info("retrieving all existing Bookings");

		List<BookingEntity> listBookingEntity = bookingRepository.findAll();
		List<BookingResponse> listBookingResponse = new ArrayList<>();

		for (BookingEntity bookingEntity : listBookingEntity) {
			BookingResponse bookingResponse = new BookingResponse(bookingEntity);

			try {
				// Cast the response body to FlightResponse
				ResponseEntity<?> flightResponseEntity = flightFeignClient
						.getFlightById(bookingEntity.getFlightNumber());
				FlightResponse flightResponse = (FlightResponse) flightResponseEntity.getBody();
				bookingResponse.setFlightResponse(flightResponse);
			} catch (Exception e) {
				log.error("Failed to fetch flight data for booking ID: {} with flight number: {}. Error: {}",
						bookingEntity.getId(), bookingEntity.getFlightNumber(), e.getMessage());
				bookingResponse.setFlightResponse(null);
			}

			listBookingResponse.add(bookingResponse);
		}

		log.info("retrieved all existing Bookings with flight data");
		return listBookingResponse;
	}

	@Override
	public List<BookingResponse> getBookingsByUserEmail(String email) {
		log.info("retrieving bookings for user email: {}", email);

		// Find bookings by user email
		List<BookingEntity> listBookingEntity = bookingRepository.findByEmail(email);
		List<BookingResponse> listBookingResponse = new ArrayList<>();

		for (BookingEntity bookingEntity : listBookingEntity) {
			BookingResponse bookingResponse = new BookingResponse(bookingEntity);

			try {
				// Get flight data for each booking
				ResponseEntity<FlightResponse> flightResponseEntity = flightFeignClient
						.getFlightById(bookingEntity.getFlightNumber());
				bookingResponse.setFlightResponse(flightResponseEntity.getBody());
			} catch (Exception e) {
				log.error("Failed to fetch flight data for booking ID: {} with flight number: {}. Error: {}",
						bookingEntity.getId(), bookingEntity.getFlightNumber(), e.getMessage());
				bookingResponse.setFlightResponse(null);
			}

			listBookingResponse.add(bookingResponse);
		}

		log.info("retrieved {} bookings for user email: {}", listBookingResponse.size(), email);
		return listBookingResponse;
	}
}