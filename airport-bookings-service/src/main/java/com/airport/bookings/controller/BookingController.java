/**
 * @author SIRAJ CHAUDHARY
 * 
 * https://github.com/SirajChaudhary
 * 
 * https://www.linkedin.com/in/sirajchaudhary/
 */

package com.airport.bookings.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.airport.bookings.request.Booking;
import com.airport.bookings.response.BookingResponse;
import com.airport.bookings.service.BookingService;
import com.airport.bookings.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

@RestController
public class BookingController {

	private static final Logger log = LoggerFactory.getLogger(BookingController.class);

	@Autowired
	private BookingService bookingService;

	@Autowired
	private JwtUtil jwtUtil;

	/*
	 * API to book a flight ticket
	 * 
	 * @param Booking (fullname, mobile, email, address, flightNumber(FK))
	 * 
	 * @return BookingResponse (id, mobile, email, address, FlightResponse object)
	 */
	@PostMapping("/api/v1/bookings")
	public ResponseEntity<BookingResponse> createBooking(@RequestBody Booking booking) {
		BookingResponse bookingResponse = bookingService.createBooking(booking);
		return new ResponseEntity<>(bookingResponse, HttpStatus.CREATED);
	}

	@GetMapping("/api/v1/bookings")
	public ResponseEntity<List<BookingResponse>> getAllBookings(HttpServletRequest request) {
		try {
			// Step 1: Extract JWT token from Authorization header
			String token = jwtUtil.extractTokenFromRequest(request);

			if (token == null) {
				log.warn("No authorization token provided");
				return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
			}

			// Step 2: Decode JWT token
			Map<String, Object> decodedToken = jwtUtil.decodeJwtToken(token);

			// Step 3: Check if token is expired
			if (jwtUtil.isTokenExpired(decodedToken)) {
				log.warn("Token has expired");
				return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
			}

			// Step 4: Check if user is admin using the exact path you specified
			boolean isAdmin = jwtUtil.isUserAdmin(decodedToken);

			List<BookingResponse> listBookingResponse;

			if (isAdmin) {
				// Step 5a: Admin gets ALL bookings
				log.info("Admin user accessing all bookings");
				listBookingResponse = bookingService.getAllBookings();
			} else {
				// Step 5b: Regular user gets only THEIR bookings
				String userEmail = jwtUtil.getUserEmailFromToken(decodedToken);
				if (userEmail == null) {
					log.error("Unable to extract user email from token");
					return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
				}
				log.info("Regular user {} accessing their bookings only", userEmail);
				listBookingResponse = bookingService.getBookingsByUserEmail(userEmail);
			}

			return new ResponseEntity<>(listBookingResponse, HttpStatus.OK);

		} catch (Exception e) {
			log.error("Error processing request: {}", e.getMessage());
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	/*
	 * API to fetch a booking details by bookingId
	 * 
	 * @param bookingId
	 * 
	 * @return BookingResponse (id, mobile, email, address, FlightResponse object)
	 */
	@GetMapping("/api/v1/bookings/{id}")
	public ResponseEntity<BookingResponse> getBookingById(@PathVariable long id) {
		BookingResponse bookingResponse = bookingService.getBookingById(id);
		return new ResponseEntity<>(bookingResponse, HttpStatus.OK);
	}

	/*
	 * API to fetch a booking details by pnrNumber
	 * 
	 * @param pnrNumber
	 * 
	 * @return BookingResponse (id, mobile, email, address, FlightResponse object)
	 */
	@GetMapping("/api/v1/bookings/find-by-pnr")
	public ResponseEntity<BookingResponse> findBookingByPNRNumber(@RequestParam String pnrNumber) {
		BookingResponse bookingResponse = bookingService.findBookingByPNRNumber(pnrNumber);
		return new ResponseEntity<>(bookingResponse, HttpStatus.OK);
	}
}